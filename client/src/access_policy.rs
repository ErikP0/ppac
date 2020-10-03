use std::path::{PathBuf, Path, Component};
use crate::error::Error;
use std::fs::File;
use std::io::{BufReader, Read};
use zokrates_core::ir::{Prog as Program};
use zokrates_core::proof_system::{ProofSystem, SetupKeypair};
use zokrates_core::proof_system::bellman::groth16::{G16, VerificationKey as G16VerificationKey, ProofPoints as G16ProofPoints};
use zokrates_field::{Field as _, bn128::FieldPrime};
use itertools::Itertools;
use ethereum_types::{U256, H256};
use crate::document::ProvingKey;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use regex::Regex;
use zokrates_core::compile::{CompileConfig, CompilationArtifacts};

lazy_static! {
    static ref PROVING_SCHEME: G16 = G16 {};
}

lazy_static! {
    static ref ZOK_COMPILE_CONFIG: CompileConfig = CompileConfig::default()
        .with_is_release(true);
}

lazy_static! {
    /// pattern with 3 capture groups
    /// group 1: indent of main function
    /// group 2: function arguments
    /// group 3: function returns
    static ref MAIN_FUN: Regex = Regex::new(r#"^([ \t]*)def main\(([^\)]*)\)[ \t]*->[ \t]*\(([^\)]*)\):[ \t]*$"#)
        .unwrap();
}

lazy_static! {
    static ref EMPTY_MAIN_ARGS: Regex = Regex::new(r#"^[ \t]*$"#).unwrap();
}

const BINDING_ARGS: &str = "private field[2] private_binding__, field[2] public_binding__";
const BINDING_CONSTRAINT1: &str = "private_binding__[0] == public_binding__[0]";
const BINDING_CONSTRAINT2: &str = "private_binding__[1] == public_binding__[1]";

#[derive(Serialize, Deserialize)]
pub struct AccessPolicy {
    compiled_proof_program: Program<FieldPrime>,
    threshold: u32,
    /// the public inputs of the circuit (except for the output 0x1)
    public_inputs: Vec<WitnessArgument>
}

impl AccessPolicy {

    fn inject_binding(program_without_binding: String) -> Result<String, Error> {
        // split line-by-line
        let lines = program_without_binding.lines();
        let mut processed = Vec::new();
        let mut found_main = false;
        for line in lines {
            if !found_main {
                // try to match
                match MAIN_FUN.captures(line) {
                    Some(capture) => {
                        // append binding
                        let indent = capture.get(1).unwrap();
                        let args = capture.get(2).unwrap();
                        let return_values = capture.get(3).unwrap();
                        let injected_main = if EMPTY_MAIN_ARGS.is_match(args.as_str()) {
                            format!("{indent}def main({binding}) -> ({returns}):", indent=indent.as_str(), binding=BINDING_ARGS,returns=return_values.as_str())
                        }else{
                            format!("{indent}def main({args}, {binding}) -> ({returns}):", indent=indent.as_str(), args=args.as_str(), binding=BINDING_ARGS, returns=return_values.as_str())
                        };
                        processed.push(injected_main);
                        processed.push(format!("{indent}    {c}", indent=indent.as_str(), c=BINDING_CONSTRAINT1));
                        processed.push(format!("{indent}    {c}", indent=indent.as_str(), c=BINDING_CONSTRAINT2));
                        found_main = true;
                    },
                    None => {
                        processed.push(line.to_string());
                    }
                }
            }else{
                processed.push(line.to_string());
            }
        }

        if !found_main {
            return Err(Error::Zokrates("Main function not found".to_string()));
        }
        Ok(processed.into_iter().join("\n"))
    }

    fn compile(source: String, location: PathBuf, zok_std_lib: &Path) -> Result<CompilationArtifacts<FieldPrime>, Error> {
        let resolver = ImportResolver {
            zok_home: zok_std_lib.to_path_buf(),
        };
        zokrates_core::compile::compile(source, location, Some(&resolver), &*ZOK_COMPILE_CONFIG)
            .map_err(|zok_err| Error::Zokrates(format!("Compile error: {}", zok_err.0.iter().map(|compile_error| format!("{}", compile_error.value())).join("\n\n"))))
    }

    pub fn new(proof_file: &Path, threshold: u32, public_inputs: Vec<WitnessArgument>, zok_std_lib: &Path) -> Result<AccessPolicy, Error> {
        // compile circuit
        let file = File::open(&proof_file)
            .map_err(|why| Error::Io(format!("couldn't open {}: {}", &proof_file.display(), why)))?;

        let mut reader = BufReader::new(file);
        let circuit = {
            let mut s = String::new();
            reader.read_to_string(&mut s).map_err(|err| Error::Io(format!("when reading {}: {}", &proof_file.display(), err)))?;
            s
        };
        let circuit_with_binding = Self::inject_binding(circuit)?;
        let compile_artifacts = Self::compile(circuit_with_binding, proof_file.to_path_buf(), zok_std_lib)?;

        // check that exactly 1 field prime is returned
        if compile_artifacts.prog().main.returns.len() != 1 {
            return Err(Error::Zokrates("the circuit must return exactly one field prime".to_string()));
        }

        let public_inputs_len = public_inputs.iter().map(|arg| arg.encode_as_field_prime())
            .flatten().count();

        // verify number of public inputs
        let expected_public_inputs_len = compile_artifacts.prog().parameters().iter().filter(|param| !param.private).count();
        // the callers public inputs don't contain the replay protection (+2)
        if expected_public_inputs_len != public_inputs_len + 2 {
            return Err(Error::Zokrates("the number of public inputs doesn't match".to_string()));
        }

        Ok(AccessPolicy {
            compiled_proof_program: compile_artifacts.prog().clone(),
            threshold,
            public_inputs
        })
    }

    pub fn new_precompiled(program: Program<FieldPrime>, threshold: u32, public_inputs: Vec<WitnessArgument>) -> AccessPolicy {
        AccessPolicy {
            compiled_proof_program: program,
            threshold,
            public_inputs
        }
    }

    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    pub fn public_inputs(&self) -> Vec<U256> {
        self.public_inputs.iter().map(|arg| arg.encode_as_solidity_input()).flatten().collect()
    }

    pub fn setup(&self) -> Result<SetupKeypair<VerificationKey>,Error> {
        let program = self.compiled_proof_program.clone();

        let keypair = G16::setup(program);
        Ok(SetupKeypair::new(VerificationKey(keypair.vk), keypair.pk))
    }

    pub fn fill_in(self, witness: Vec<WitnessArgument>) -> FilledInAccessPolicy {
        FilledInAccessPolicy {
            policy: self,
            witness
        }
    }

    #[cfg(test)]
    pub fn knowledge_of_root(square: U256, threshold: u32) -> Self {
        let zok_home = Path::new("test_res/stdlib");
        AccessPolicy::new(&Path::new("test_res/circuit_root.zok"), threshold, vec![WitnessArgument::Number(vec![square])], zok_home)
            .unwrap()
    }
}

struct ImportResolver {
    zok_home: PathBuf
}

impl zokrates_common::Resolver<std::io::Error> for ImportResolver {
    fn resolve(&self, current_location: PathBuf, import_location: PathBuf) -> Result<(String, PathBuf), std::io::Error> {
        // Code adapted from zokrates_fs_resolver::FileSystemResolver
        let source = Path::new(&import_location);

        if !current_location.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{} was expected to be a file", current_location.display()),
            ));
        }

        // paths starting with `./` or `../` are interpreted relative to the current file
        // other paths `abc/def` are interpreted relative to zok_home
        let base = match source.components().next() {
            Some(Component::CurDir) | Some(Component::ParentDir) => {
                PathBuf::from(current_location).parent().unwrap().into()
            }
            _ => self.zok_home.clone(),
        };

        let path_owned = base
            .join(PathBuf::from(import_location.clone()))
            .with_extension("zok");

        if !path_owned.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("No file found at {}", import_location.display()),
            ));
        }

        let source = std::fs::read_to_string(&path_owned)?;
        Ok((source, path_owned))
    }
}

pub struct FilledInAccessPolicy {
    policy: AccessPolicy,
    witness: Vec<WitnessArgument>
}

impl FilledInAccessPolicy {
    pub fn compute_zk_proof(&self, proving_key: &ProvingKey, nonce: H256) -> Result<Proof, Error> {
        let circuit = &self.policy.compiled_proof_program;
        let args = self.witness.iter().map(|witness_arg| witness_arg.encode_as_field_prime()).flatten()
            .chain(self.policy.public_inputs.iter().map(|witness_arg| witness_arg.encode_as_field_prime()).flatten())
            // private field[2] private_binding__
            .chain(WitnessArgument::from_h256(nonce.clone()).encode_as_field_prime())
            // field[2] public_binding__
            .chain(WitnessArgument::from_h256(nonce).encode_as_field_prime())
            .collect();
        let interpreter = zokrates_core::ir::Interpreter::default();
        let witness = interpreter.execute(circuit, &args).map_err(|interpereter_error| Error::Zokrates(format!("Error when computing the witness: {}", interpereter_error)))?;
        let proof = G16::generate_proof(circuit.clone(), witness, proving_key.clone());
        Ok(Proof::new(proof))
    }
}

/// Zokrates BN256 prime modulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617
const FIELD_PRIME_MODULUS: U256 = U256([0x43e1f593f0000001, 0x2833e84879b97091, 0xb85045b68181585d, 0x30644e72e131a029]);

#[derive(Clone, Serialize, Deserialize)]
pub enum WitnessArgument {
    Number(Vec<U256>)
}

impl WitnessArgument {
    pub fn from_dec_string(dec_string: &str) -> Result<WitnessArgument, Error> {
        let value = U256::from_dec_str(dec_string)
            .map_err(|err| Error::Zokrates(format!("Cannot parse '{}' as decimal number: {}", dec_string, err)))?;
        // must be less than field prime p
        if value < FIELD_PRIME_MODULUS {
            Ok(WitnessArgument::Number(vec![value]))
        }else{
            Err(Error::Zokrates(format!("Argument {} is larger than the field prime modulus. Consider splitting the argument.", dec_string)))
        }
    }

    pub fn from_h256(u: H256) -> WitnessArgument {
        let as_str = format!("{:x}", u);
        debug_assert_eq!(as_str.len(), 64);
        let lower: U256 = format!("00000000000000000000000000000000{}", &as_str[32..64]).parse().unwrap();
        let higher: U256 = format!("00000000000000000000000000000000{}", &as_str[0..32]).parse().unwrap();
        WitnessArgument::Number(vec![higher,lower])
    }

    pub fn encode_as_field_prime(&self) -> Vec<FieldPrime> {
        match self {
            WitnessArgument::Number(numbers) => numbers.iter()
                .map(|num| {
                    let num_as_dec_str = format!("{}", num);
                    FieldPrime::try_from_dec_str(&num_as_dec_str).unwrap()
                })
                .collect()
        }
    }

    pub fn encode_as_solidity_input(&self) -> Vec<U256> {
        match self {
            WitnessArgument::Number(numbers) => numbers.clone()
        }
    }

    #[cfg(test)]
    pub fn one() -> Self {
        WitnessArgument::Number(vec![U256([1,0,0,0])])
    }
}

pub struct VerificationKey(G16VerificationKey);

impl Serialize for VerificationKey {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
        S: Serializer {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VerificationKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error> where
        D: Deserializer<'de> {
        Ok(VerificationKey(<G16VerificationKey as Deserialize<'de>>::deserialize(deserializer)?))
    }
}

impl Clone for VerificationKey {
    fn clone(&self) -> Self {
        let json = serde_json::to_string(&self.0).unwrap();
        VerificationKey(serde_json::from_str(&json).unwrap())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DecodedG16VK {
    alpha: [H256; 2],
    beta: [[H256; 2]; 2],
    gamma: [[H256; 2]; 2],
    delta: [[H256; 2]; 2],
    gamma_abc: Vec<[H256; 2]>,
}

#[cfg(test)]
fn to_h256(u: U256) -> H256 {
    let mut h = [0; 32];
    u.to_big_endian(&mut h);
    H256(h)
}

fn to_u256(h: H256) -> U256 {
    U256::from_big_endian(&h.0)
}

impl VerificationKey {
    /// ethabi 12.0.0 doesn't support nested arrays (see https://github.com/openethereum/ethabi/pull/186)
    /// so we flatten the array before passing to encode
    pub fn ethabi_compliant(self) -> ([U256;2], [U256; 4], [U256; 4], [U256; 4], Vec<U256>) {
        let decoded = serde_json::from_value::<DecodedG16VK>(serde_json::to_value(self.0).unwrap()).unwrap();
        let gamma_abc: Vec<U256> = decoded.gamma_abc.iter().map(|p| p.iter().cloned()).flatten().map(|h| to_u256(h)).collect();
        ([to_u256(decoded.alpha[0]), to_u256(decoded.alpha[1])],
         [to_u256(decoded.beta[0][0]), to_u256(decoded.beta[0][1]), to_u256(decoded.beta[1][0]), to_u256(decoded.beta[1][1])],
         [to_u256(decoded.gamma[0][0]), to_u256(decoded.gamma[0][1]), to_u256(decoded.gamma[1][0]), to_u256(decoded.gamma[1][1])],
         [to_u256(decoded.delta[0][0]), to_u256(decoded.delta[0][1]), to_u256(decoded.delta[1][0]), to_u256(decoded.delta[1][1])],
        gamma_abc)
    }

    #[cfg(test)]
    pub fn from_ethabi(a: [U256;2], b: [U256; 4], gamma: [U256; 4], delta: [U256; 4], gamma_abc: Vec<U256>) -> Result<Self, Error> {
        if gamma_abc.len() % 2 != 0 {
            return Err(Error::Zokrates("gamma_abc must have even length".to_string()));
        }
        let gamma_abc: Vec<_> = (0..gamma_abc.len()/2).map(|i| [to_h256(gamma_abc[2*i]), to_h256(gamma_abc[2*i+1])])
            .collect();
        let vk = DecodedG16VK {
            alpha: [to_h256(a[0]), to_h256(a[1])],
            beta: [[to_h256(b[0]), to_h256(b[1])], [to_h256(b[2]), to_h256(b[3])]],
            gamma: [[to_h256(gamma[0]), to_h256(gamma[1])], [to_h256(gamma[2]), to_h256(gamma[3])]],
            delta: [[to_h256(delta[0]), to_h256(delta[1])], [to_h256(delta[2]), to_h256(delta[3])]],
            gamma_abc,
        };
        let serialized = serde_json::to_value(vk).unwrap();
        Ok(VerificationKey(serde_json::from_value(serialized).unwrap()))
    }
}


pub struct Proof(zokrates_core::proof_system::Proof<G16ProofPoints>);

impl Clone for Proof {
    fn clone(&self) -> Self {
        let json = serde_json::to_string(&self.0).unwrap();
        Proof(serde_json::from_str(&json).unwrap())
    }
}

#[derive(Deserialize)]
struct DecodedG16Proof {
    a: [H256; 2],
    b: [[H256; 2]; 2],
    c: [H256; 2]
}

impl Proof {
    fn new(proof: zokrates_core::proof_system::Proof<G16ProofPoints>) -> Self {
        Proof(proof)
    }

    fn proof_points(self) -> G16ProofPoints {
        let value = serde_json::to_value(self.0).unwrap();
        let value = value.as_object().unwrap().get("proof").unwrap().clone();
        serde_json::from_value(value).unwrap()
    }

    pub fn encode_as_payload(self) -> Vec<U256> {
        let decoded = serde_json::from_value::<DecodedG16Proof>(serde_json::to_value(self.proof_points()).unwrap()).unwrap();
        vec![decoded.a[0], decoded.a[1], decoded.b[0][0], decoded.b[0][1], decoded.b[1][0], decoded.b[1][1], decoded.c[0], decoded.c[1]]
            .into_iter()
            .map(|h| to_u256(h))
            .collect()
    }
}
//
// pub struct G16VerifyingKey {
//     a: [U256; 2],
//     b: [[U256; 2]; 2],
//     gamma: [[U256; 2]; 2],
//     delta: [[U256; 2]; 2],
//     gamma_abc: Vec<[U256;2]>
// }
//
// lazy_static! {
//     static ref G1_PATTERN: Regex = Regex::new(r"\s*vk\.(?:alpha|gamma_abc\[\d+\])\s*=\s*0x([A-Fa-f0-9]{64}),\s*0x([A-Fa-f0-9]{64})\s*").unwrap();
//     static ref G2_PATTERN: Regex = Regex::new(r"\s*vk\.(?:beta|gamma|delta)\s*=\s*\[0x([A-Fa-f0-9]{64}),\s*0x([A-Fa-f0-9]{64})\s*\],\s*\[0x([A-Fa-f0-9]{64}),\s*0x([A-Fa-f0-9]{64})\s*\]\s*").unwrap();
//     static ref GAMMA_ABC_LEN_PATTERN: Regex = Regex::new(r"\s*vk\.gamma_abc\.len\(\)\s*=\s*(\d+)\s*").unwrap();
// }
//
// impl G16VerifyingKey {
//
//     /// panics if `vk` is not in the correct format
//     pub fn parse_zokrates_vk(vk: &str) -> Self {
//         let mut lines = vk.lines();
//         let alpha = lines.next().unwrap();
//         let alpha = G1_PATTERN.captures(alpha).unwrap();
//         let a: [U256; 2] = [alpha[1].parse().unwrap(), alpha[2].parse().unwrap()];
//
//         let beta = lines.next().unwrap();
//         let beta = G2_PATTERN.captures(beta).unwrap();
//         let b: [[U256;2]; 2] = [[beta[1].parse().unwrap(), beta[2].parse().unwrap()], [beta[3].parse().unwrap(), beta[4].parse().unwrap()]];
//
//         let gamma = lines.next().unwrap();
//         let gamma = G2_PATTERN.captures(gamma).unwrap();
//         let gamma: [[U256;2]; 2] = [[gamma[1].parse().unwrap(), gamma[2].parse().unwrap()], [gamma[3].parse().unwrap(), gamma[4].parse().unwrap()]];
//
//         let delta = lines.next().unwrap();
//         let delta = G2_PATTERN.captures(delta).unwrap();
//         let delta: [[U256;2]; 2] = [[delta[1].parse().unwrap(), delta[2].parse().unwrap()], [delta[3].parse().unwrap(), delta[4].parse().unwrap()]];
//
//         let gamma_abc_len = lines.next().unwrap();
//         let gamma_abc_len = GAMMA_ABC_LEN_PATTERN.captures(gamma_abc_len).unwrap();
//         let gamma_abc_len: usize = usize::from_str(&gamma_abc_len[1]).unwrap();
//
//         let gamma_abc: Vec<[U256;2]> = (0..gamma_abc_len).map(|_| {
//             let gamma_abc = lines.next().unwrap();
//             let gamma_abc = G1_PATTERN.captures(gamma_abc).unwrap();
//             [gamma_abc[1].parse::<U256>().unwrap(), gamma_abc[2].parse::<U256>().unwrap()]
//         }).collect();
//
//         G16VerifyingKey {
//             a,
//             b,
//             gamma,
//             delta,
//             gamma_abc,
//         }
//     }
//
//     /// ethabi 12.0.0 doesn't support nested arrays (see https://github.com/openethereum/ethabi/pull/186)
//     /// so we flatten the array before passing to encode
//     pub fn ethabi_compliant(self) -> ([U256;2], [U256; 4], [U256; 4], [U256; 4], Vec<U256>) {
//         let gamma_abc: Vec<U256> = self.gamma_abc.iter().map(|p| p.iter().cloned()).flatten().collect();
//         (self.a, [self.b[0][0], self.b[0][1], self.b[1][0], self.b[1][1]], [self.gamma[0][0], self.gamma[0][1], self.gamma[1][0], self.gamma[1][1]], [self.delta[0][0], self.delta[0][1], self.delta[1][0], self.delta[1][1]], gamma_abc)
//     }
//
//     pub fn from_ethabi(a: [U256;2], b: [U256; 4], gamma: [U256; 4], delta: [U256; 4], gamma_abc: Vec<U256>) -> Result<G16VerifyingKey, Error> {
//         if gamma_abc.len() % 2 != 0 {
//             return Err(Error::Zokrates("gamma_abc must have even length".to_string()));
//         }
//         let gamma_abc = (0..gamma_abc.len()/2).map(|i| [gamma_abc[2*i], gamma_abc[2*i+1]])
//             .collect();
//         Ok(G16VerifyingKey {
//             a,
//             b: [[b[0], b[1]], [b[2], b[3]]],
//             gamma: [[gamma[0], gamma[1]], [gamma[2], gamma[3]]],
//             delta: [[delta[0], delta[1]], [delta[2], delta[3]]],
//             gamma_abc
//         })
//     }
// }

// impl TryFrom<&zokrates_core::proof_system::SetupKeypair> for G16VerifyingKey {
//     fn try_from(key_pair: &zokrates_core::proof_system::SetupKeypair) -> Self {
//
//     }
// }

#[cfg(test)]
pub mod test {
    use crate::error::Error;
    use crate::access_policy::{AccessPolicy, WitnessArgument, FilledInAccessPolicy, VerificationKey, Proof};
    use std::path::{Path, PathBuf};
    use ethereum_types::{U256, H256, U128};
    use zokrates_core::ir::{Prog as Program};
    use zokrates_core::proof_system::ProofSystem;
    use zokrates_core::proof_system::bellman::groth16::G16;
    use zokrates_field::bn128::FieldPrime;
    use std::fs::File;
    use std::io::Read;

    pub fn verify_g16_proof(proof: Proof, verifying_key: VerificationKey, public_inputs: &[WitnessArgument]) -> bool {
        let inputs: Vec<U256> = public_inputs.iter()
            .map(|arg| match arg {
                WitnessArgument::Number(values) => values.iter().cloned()
            })
            .flatten()
            .collect();
        let mut json = serde_json::to_value(proof.0).unwrap();
        let proof_obj = json.as_object_mut().unwrap();
        proof_obj.insert("inputs".to_string(), serde_json::to_value(inputs).unwrap());
        let proof_with_inputs = serde_json::from_value(json).unwrap();
        <G16 as ProofSystem<FieldPrime>>::verify(verifying_key.0, proof_with_inputs)
    }

    #[test]
    fn inject_binding_works() {
        let minimal_program =
        r#"
        def main() -> (field):
            field a = 1
            field b = 2
            return a + b
        "#;
        let expected =
        r#"
        def main(private field[2] private_binding__, field[2] public_binding__) -> (field):
            private_binding__[0] == public_binding__[0]
            private_binding__[1] == public_binding__[1]
            field a = 1
            field b = 2
            return a + b
        "#;
        assert_eq!(expected, &AccessPolicy::inject_binding(minimal_program.to_string()).unwrap());

        let program_with_inputs =
        r#"
        // A circuit file that depends on zokrates standard library functions

        import "utils/pack/unpack128" as unpack128

        def main(private field x, field y) -> (bool[128]):
            bool[128] h = unpack128(x)
            y == 1
            return h
        "#;
        let expected =
        r#"
        // A circuit file that depends on zokrates standard library functions

        import "utils/pack/unpack128" as unpack128

        def main(private field x, field y, private field[2] private_binding__, field[2] public_binding__) -> (bool[128]):
            private_binding__[0] == public_binding__[0]
            private_binding__[1] == public_binding__[1]
            bool[128] h = unpack128(x)
            y == 1
            return h
        "#;
        assert_eq!(expected, &AccessPolicy::inject_binding(program_with_inputs.to_string()).unwrap());
    }

    fn compile(file_path: PathBuf) -> Program<FieldPrime> {
        let mut file = File::open(&file_path).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        AccessPolicy::compile(content, file_path, Path::new("test_res/stdlib")).unwrap().prog().clone()
    }

    #[test]
    fn zokrates_setup_works() {
        let policy = AccessPolicy {
            compiled_proof_program: compile(Path::new("test_res/circuit_no_std.zok").to_path_buf()),
            threshold: 0,
            public_inputs: vec![],
        };
        policy.setup().unwrap();
    }

    #[test]
    fn zokrates_setup_works_when_using_std() {
        let policy = AccessPolicy {
            compiled_proof_program: compile(Path::new("test_res/circuit_std.zok").to_path_buf()),
            threshold: 0,
            public_inputs: vec![],
        };
        policy.setup().unwrap();
    }

    #[test]
    fn zokrates_compute_proof_works() {
        let policy = AccessPolicy::new(&Path::new("test_res/circuit_root.zok"), 0, vec![WitnessArgument::Number(vec!["4ec4".parse().unwrap()])], Path::new("test_res/stdlib"))
            .unwrap();
        let args = vec![WitnessArgument::Number(vec!["8e".parse().unwrap()]), WitnessArgument::Number(vec!["4ec4".parse().unwrap()])];

        let keypair = policy.setup().unwrap();

        let filled_in = FilledInAccessPolicy {
            policy,
            witness: args
        };

        let nonce: H256 = "1539c63cd6109c8cc851d310028de618336dcd9a73de72babf1dfd49bf871bac".parse().unwrap();
        let proof = filled_in.compute_zk_proof(&keypair.pk, nonce.clone()).unwrap();
        assert!(verify_g16_proof(proof, keypair.vk, &vec![WitnessArgument::Number(vec!["4ec4".parse().unwrap()]), WitnessArgument::from_h256(nonce), WitnessArgument::Number(vec![U256([1,0,0,0])])]));
    }

    // #[test]
    // fn construct_g16_vk_works() {
    //     let policy = AccessPolicy {
    //         proof_file: Path::new("test_res/circuit_no_std.zok").to_path_buf(),
    //         threshold: 0,
    //         public_inputs: vec![],
    //     };
    //     let setup = policy.setup().unwrap();
    //     // doesn't panic
    //     G16VerifyingKey::parse_zokrates_vk(&setup.vk);
    // }

    #[test]
    fn compute_proof_errors_when_invalid_witness_is_provided() {
        let policy = AccessPolicy::new(&Path::new("test_res/circuit_root.zok"), 0, vec![WitnessArgument::Number(vec!["4ec4".parse().unwrap()])], Path::new("test_res/stdlib"))
            .unwrap();
        // 4 is not the root of 20164
        let args = vec![WitnessArgument::Number(vec!["4".parse().unwrap()]), WitnessArgument::Number(vec!["4ec4".parse().unwrap()])];

        let proving_key = policy.setup().unwrap().pk;

        let filled_in = FilledInAccessPolicy {
            policy,
            witness: args
        };

        let nonce = "1539c63cd6109c8cc851d310028de618336dcd9a73de72babf1dfd49bf871bac".parse().unwrap();
        match filled_in.compute_zk_proof(&proving_key, nonce) {
            Err(Error::Zokrates(_)) => (),
            _ => panic!("unexpected"),
        }
    }

    #[test]
    fn proof_replay_protection_works() {
        let policy = AccessPolicy::new(&Path::new("test_res/circuit_root.zok"), 0, vec![WitnessArgument::Number(vec!["4ec4".parse().unwrap()])], Path::new("test_res/stdlib"))
            .unwrap();
        let args = vec![WitnessArgument::Number(vec!["8e".parse().unwrap()]), WitnessArgument::Number(vec!["4ec4".parse().unwrap()])];

        let keypair = policy.setup().unwrap();

        let filled_in = FilledInAccessPolicy {
            policy,
            witness: args
        };

        let nonce: H256 = "1539c63cd6109c8cc851d310028de618336dcd9a73de72babf1dfd49bf871bac".parse().unwrap();
        let proof = filled_in.compute_zk_proof(&keypair.pk, nonce.clone()).unwrap();
        assert!(verify_g16_proof(proof.clone(), keypair.vk.clone(), &vec![WitnessArgument::Number(vec!["4ec4".parse().unwrap()]), WitnessArgument::from_h256(nonce), WitnessArgument::Number(vec![U256([1,0,0,0])])]));

        // replay with different nonce
        let different_nonce: H256 = "1539c63cd6109c8cc851d310028de618336dcd9a73de72babf1dfd49bf871bad".parse().unwrap();
        assert!(!verify_g16_proof(proof, keypair.vk, &vec![WitnessArgument::Number(vec!["4ec4".parse().unwrap()]), WitnessArgument::from_h256(different_nonce), WitnessArgument::Number(vec![U256([1,0,0,0])])]));
    }

    #[test]
    fn verification_key_to_abi_encoded_works() {
        let policy = AccessPolicy {
            compiled_proof_program: compile(Path::new("test_res/circuit_no_std.zok").to_path_buf()),
            threshold: 0,
            public_inputs: vec![],
        };
        let vk = policy.setup().unwrap().vk;
        let (a,b,gamma,delta,gamma_abc) = vk.ethabi_compliant();
        // try to reconstruct
        VerificationKey::from_ethabi(a,b,gamma,delta,gamma_abc).unwrap();
    }

    #[test]
    fn witness_argument_from_h256() {
        let h: H256 = "1936c240636390dc823e3a728e94b208eb53c6756d81da57ec3425e05d43ac10".parse().unwrap();
        let arg = WitnessArgument::from_h256(h);
        // expect higher 128bit | lower 128bit
        let higher: U128 = "1936c240636390dc823e3a728e94b208".parse().unwrap();
        let lower: U128 = "eb53c6756d81da57ec3425e05d43ac10".parse().unwrap();
        let vec = match arg {
            WitnessArgument::Number(vec) => vec,
        };
        assert_eq!(vec.len(), 2);
        let higher_u256 = U256::from(higher);
        let lower_u256 = U256::from(lower);
        assert_eq!(format!("{:x}",vec[0]), format!("{:x}", higher_u256));
        assert_eq!(vec[1], lower_u256);
    }
}
