use std::fmt;
use parity_crypto::publickey::Error as PublicCryptoError;
use parity_crypto::error::SymmError as SymmCryptoError;
use hyper::Error as HyperError;
use hyper::http::Error as HttpError;
use ethereum_types::H256;
use std::process::Termination;

pub enum Error {
    Crypto(String),
    SecretStore(String),
    Http(HttpError),
    Hyper(HyperError),
    Io(String),
    Zokrates(String),
    DocumentNotFound(H256),
    AccessDenied(H256),
    Eth(String)
}

impl std::error::Error for Error {

}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Crypto(crypto_err) => write!(f, "CryptoError({})", crypto_err),
            Error::SecretStore(msg) => write!(f, "SecretStoreError({})", msg),
            Error::Http(http_error) => write!(f, "HttpError({})", http_error),
            Error::Hyper(hyper_error) => write!(f, "HyperError({})", hyper_error),
            Error::Io(msg) => write!(f, "IoError({})", msg),
            Error::Zokrates(msg) => write!(f, "ZokratesError({})", msg),
            Error::DocumentNotFound(document_id) => write!(f, "DocumentNotFound(id={:x})", document_id),
            Error::AccessDenied(document_id) => write!(f, "AcceddDenied(id={:x})", document_id),
            Error::Eth(msg) => write!(f, "EthError({})", msg),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Crypto(crypto_err) => write!(f, "Error({:?})", crypto_err),
            Error::SecretStore(msg) => write!(f, "SecretStoreError({})", msg),
            Error::Http(http_error) => write!(f, "HttpError({:?})", http_error),
            Error::Hyper(hyper_error) => write!(f, "HyperError({:?})", hyper_error),
            Error::Io(msg) => write!(f, "IoError({})", msg),
            Error::Zokrates(msg) => write!(f, "ZokratesError({})", msg),
            Error::DocumentNotFound(document_id) => write!(f, "DocumentNotFound(id={:x})", document_id),
            Error::AccessDenied(document_id) => write!(f, "AcceddDenied(id={:x})", document_id),
            Error::Eth(msg) => write!(f, "EthError({})", msg),
        }
    }
}

impl From<PublicCryptoError> for Error {
    fn from(crypto_err: PublicCryptoError) -> Self {
        Error::Crypto(format!("{}", crypto_err))
    }
}

impl From<SymmCryptoError> for Error {
    fn from(crypto_err: SymmCryptoError) -> Self {
        Error::Crypto(format!("{}", crypto_err))
    }
}

impl From<HttpError> for Error {
    fn from(http_err: HttpError) -> Self {
        Error::Http(http_err)
    }
}

impl From<HyperError> for Error {
    fn from(hyper_err: HyperError) -> Self {
        Error::Hyper(hyper_err)
    }
}

impl From<std::io::Error> for Error {
    fn from(io_err: std::io::Error) -> Self {
        Error::Io(format!("{}", io_err))
    }
}

impl Termination for Error {
    fn report(self) -> i32 {
        match self {
            Error::Zokrates(_) => 2,
            Error::Crypto(_) => 3,
            Error::SecretStore(_) => 4,
            Error::Http(_) => 5,
            Error::Hyper(_) => 6,
            Error::Io(_) => 7,
            Error::DocumentNotFound(_) => 8,
            Error::AccessDenied(_) => 9,
            Error::Eth(_) => 10,
        }
    }
}