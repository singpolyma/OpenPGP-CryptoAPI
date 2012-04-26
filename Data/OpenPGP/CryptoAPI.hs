module Data.OpenPGP.CryptoAPI where

import Numeric
import Data.Word
import Data.Char
import Data.Binary
import Crypto.Classes hiding (hash)
import Crypto.Hash.MD5 (MD5)
import Crypto.Hash.SHA1 (SHA1)
import Crypto.Hash.RIPEMD160 (RIPEMD160)
import Crypto.Hash.SHA256 (SHA256)
import Crypto.Hash.SHA384 (SHA384)
import Crypto.Hash.SHA512 (SHA512)
import Crypto.Hash.SHA224 (SHA224)
import qualified Data.Serialize as Serialize (encode)
import qualified Crypto.Cipher.RSA as RSA
import qualified Crypto.Cipher.DSA as DSA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LZ

import qualified Data.OpenPGP as OpenPGP

-- | Generate a key fingerprint from a PublicKeyPacket or SecretKeyPacket
-- <http://tools.ietf.org/html/rfc4880#section-12.2>
fingerprint :: OpenPGP.Packet -> String
fingerprint p
	| OpenPGP.version p == 4 = snd $ hash OpenPGP.SHA1 material
	| OpenPGP.version p `elem` [2, 3] = snd $ hash OpenPGP.MD5 material
	| otherwise = error "Unsupported Packet version or type in fingerprint"
	where
	material = LZ.concat $ OpenPGP.fingerprint_material p

find_key :: OpenPGP.Message -> String -> Maybe OpenPGP.Packet
find_key = OpenPGP.find_key fingerprint

hash :: OpenPGP.HashAlgorithm -> LZ.ByteString -> (BS.ByteString, String)
hash OpenPGP.MD5 = hash_ (undefined :: MD5)
hash OpenPGP.SHA1 = hash_ (undefined :: SHA1)
hash OpenPGP.RIPEMD160 = hash_ (undefined :: RIPEMD160)
hash OpenPGP.SHA256 = hash_ (undefined :: SHA256)
hash OpenPGP.SHA384 = hash_ (undefined :: SHA384)
hash OpenPGP.SHA512 = hash_ (undefined :: SHA512)
hash OpenPGP.SHA224 = hash_ (undefined :: SHA224)
hash _ = error "Unsupported HashAlgorithm in hash"

hash_ :: (Hash c d) => d -> LZ.ByteString -> (BS.ByteString, String)
hash_ d bs = (hbs, map toUpper $ pad $ hexString $ BS.unpack $ hbs)
	where
	hbs = Serialize.encode $ hashFunc d bs
	pad s = (replicate (len - length s) '0') ++ s
	len = (outputLength `for` d) `div` 8

hexString :: [Word8] -> String
hexString = foldr (pad `oo` showHex) ""
	where
	oo = (.) . (.)
	pad s | odd $ length s = '0':s
	      | otherwise = s

-- http://tools.ietf.org/html/rfc3447#page-43
-- http://tools.ietf.org/html/rfc4880#section-5.2.2
emsa_pkcs1_v1_5_hash_padding :: OpenPGP.HashAlgorithm -> BS.ByteString
emsa_pkcs1_v1_5_hash_padding OpenPGP.MD5 = BS.pack [0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10]
emsa_pkcs1_v1_5_hash_padding OpenPGP.SHA1 = BS.pack [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]
emsa_pkcs1_v1_5_hash_padding OpenPGP.RIPEMD160 = BS.pack [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24, 0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14]
emsa_pkcs1_v1_5_hash_padding OpenPGP.SHA256 = BS.pack [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]
emsa_pkcs1_v1_5_hash_padding OpenPGP.SHA384 = BS.pack [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]
emsa_pkcs1_v1_5_hash_padding OpenPGP.SHA512 = BS.pack [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]
emsa_pkcs1_v1_5_hash_padding OpenPGP.SHA224 = BS.pack [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1C]
emsa_pkcs1_v1_5_hash_padding _ =
	error "Unsupported HashAlgorithm in emsa_pkcs1_v1_5_hash_padding."

toStrictBS :: LZ.ByteString -> BS.ByteString
toStrictBS = BS.concat . LZ.toChunks

toLazyBS :: BS.ByteString -> LZ.ByteString
toLazyBS = LZ.fromChunks . (:[])

fromJustMPI :: Maybe OpenPGP.MPI -> Integer
fromJustMPI (Just (OpenPGP.MPI x)) = x
fromJustMPI _ = error "Not a Just MPI, Data.OpenPGP.CryptoAPI"

integerBytesize :: Integer -> Int
integerBytesize i = (length $ LZ.unpack $ encode (OpenPGP.MPI i)) - 2

rsaKey :: OpenPGP.Packet -> RSA.PublicKey
rsaKey k =
	RSA.PublicKey (integerBytesize n) n (fromJustMPI $ lookup 'e' k')
	where
	n = fromJustMPI $ lookup 'n' k'
	k' = OpenPGP.key k

dsaKey :: OpenPGP.Packet -> DSA.PublicKey
dsaKey k =
	DSA.PublicKey (param 'p', param 'g', param 'q') (param 'y')
	where
	param c = fromJustMPI $ lookup c k'
	k' = OpenPGP.key k

-- | Verify a message signature
verify :: OpenPGP.Message    -- ^ Keys that may have made the signature
          -> OpenPGP.Message -- ^ LiteralData message to verify
          -> Int             -- ^ Index of signature to verify (0th, 1st, etc)
          -> Bool
verify keys message sigidx =
	case OpenPGP.key_algorithm sig of
		OpenPGP.DSA -> dsaVerify
		alg | alg `elem` [OpenPGP.RSA,OpenPGP.RSA_S] -> rsaVerify
		    | otherwise -> error ("Unsupported key algorithm " ++ show alg)
	where
	dsaVerify = let k' = dsaKey k in
		case DSA.verify dsaSig (dsaTruncate k' . bhash) k' signature_over of
			Left x -> False
			Right v -> v
	rsaVerify =
		case RSA.verify (bhash) padding (rsaKey k) signature_over rsaSig of
			Left _ -> False
			Right v -> v
	rsaSig = toStrictBS $ LZ.drop 2 $ encode (head $ OpenPGP.signature sig)
	dsaSig = let [OpenPGP.MPI r, OpenPGP.MPI s] = OpenPGP.signature sig in
		(r, s)
	dsaTruncate (DSA.PublicKey (_,_,q) _) bs =
		BS.take (integerBytesize q) bs
	bhash = fst . hash hash_algo . toLazyBS
	padding = emsa_pkcs1_v1_5_hash_padding hash_algo
	hash_algo = OpenPGP.hash_algorithm sig
	signature_over = toStrictBS $ dta `LZ.append` OpenPGP.trailer sig
	Just k = OpenPGP.signature_issuer sig >>= find_key keys
	sig = sigs !! sigidx
	(sigs, (OpenPGP.LiteralDataPacket {OpenPGP.content = dta}):_) =
		OpenPGP.signatures_and_data message
