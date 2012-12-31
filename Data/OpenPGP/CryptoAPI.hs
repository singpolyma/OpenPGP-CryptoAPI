module Data.OpenPGP.CryptoAPI (fingerprint, sign, verify, decrypt) where

import Data.Char
import Data.Bits
import Data.List (find)
import Data.Maybe (mapMaybe, catMaybes, listToMaybe)
import Control.Arrow
import Control.Applicative
import Data.Binary
import Crypto.Classes hiding (hash,sign,verify,encode)
import Crypto.Modes
import Crypto.Random (CryptoRandomGen, genBytes)
import Crypto.Hash.MD5 (MD5)
import Crypto.Hash.SHA1 (SHA1)
import Crypto.Hash.RIPEMD160 (RIPEMD160)
import Crypto.Hash.SHA256 (SHA256)
import Crypto.Hash.SHA384 (SHA384)
import Crypto.Hash.SHA512 (SHA512)
import Crypto.Hash.SHA224 (SHA224)
import Crypto.Cipher.AES (AES128,AES192,AES256)
import Crypto.Cipher.Blowfish (Blowfish)
import qualified Data.Serialize as Serialize
import qualified Crypto.Cipher.RSA as RSA
import qualified Crypto.Cipher.DSA as DSA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LZ
import qualified Data.ByteString.Lazy.UTF8 as LZ (fromString)

import qualified Data.OpenPGP as OpenPGP
import Data.OpenPGP.CryptoAPI.Util

-- | An encryption routine
type Encrypt g = (g -> LZ.ByteString -> (LZ.ByteString, g))

-- | A decryption routine
type Decrypt = (LZ.ByteString -> (LZ.ByteString, LZ.ByteString))

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
hash_ d bs = (hbs, map toUpper $ pad $ hexString $ BS.unpack hbs)
	where
	hbs = Serialize.encode $ hashFunc d bs
	pad s = replicate (len - length s) '0' ++ s
	len = (outputLength `for` d) `div` 8

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

{-
pgpCFBPrefix :: (BlockCipher k, CryptoRandomGen g) => k -> g -> (LZ.ByteString, g)
pgpCFBPrefix k g =
	(toLazyBS $ str `BS.append` BS.reverse (BS.take 2 $ BS.reverse str), g')
	where
	Right (str,g') = genBytes (blockSizeBytes `for` k) g

pgpCFB :: (BlockCipher k, CryptoRandomGen g) => k -> Encrypt g
pgpCFB k g bs = (fst $ cfb k zeroIV (bs `LZ.append` p), g)
	where
	(p,g') = pgpCFBPrefix k g
-}

pgpUnCFB :: (BlockCipher k) => k -> Decrypt
pgpUnCFB k s =
	second dropPadEnd . LZ.splitAt (1 + block) . fst . unCfb k zeroIV $ padded
	where
	dropPadEnd s = LZ.take (LZ.length s - padAmount) s
	padded = s `LZ.append` LZ.replicate padAmount 0
	padAmount = block - (LZ.length s `mod` block)
	block = fromIntegral $ blockSizeBytes `for` k

-- Drops 2 because the value is an MPI
rsaDecrypt :: RSA.PrivateKey -> BS.ByteString -> Maybe BS.ByteString
rsaDecrypt pk = hush . RSA.decrypt pk . BS.drop 2

integerBytesize :: Integer -> Int
integerBytesize i = length (LZ.unpack $ encode (OpenPGP.MPI i)) - 2

keyParam :: Char -> OpenPGP.Packet -> Integer
keyParam c k = fromJustMPI $ lookup c (OpenPGP.key k)

keyAlgorithmIs :: OpenPGP.KeyAlgorithm -> OpenPGP.Packet -> Bool
keyAlgorithmIs algo p = OpenPGP.key_algorithm p == algo

secretKeys :: OpenPGP.Message -> ([(String, RSA.PrivateKey)], [(String, DSA.PrivateKey)])
secretKeys (OpenPGP.Message keys) =
	(
		map (fingerprint &&& privateRSAkey) rsa,
		map (fingerprint &&& privateDSAkey) dsa
	)
	where
	dsa = secrets OpenPGP.DSA
	rsa = secrets OpenPGP.RSA
	secrets algo = filter (allOf [isSecretKey, keyAlgorithmIs algo]) keys

privateRSAkey :: OpenPGP.Packet -> RSA.PrivateKey
privateRSAkey k =
	-- Invert p and q because u is pinv not qinv
	RSA.PrivateKey pubkey d q p
		(d `mod` (q-1))
		(d `mod` (p-1))
		(keyParam 'u' k)
	where
	d = keyParam 'd' k
	p = keyParam 'p' k
	q = keyParam 'q' k
	pubkey = rsaKey k

rsaKey :: OpenPGP.Packet -> RSA.PublicKey
rsaKey k =
	RSA.PublicKey (integerBytesize n) n (keyParam 'e' k)
	where
	n = keyParam 'n' k

privateDSAkey :: OpenPGP.Packet -> DSA.PrivateKey
privateDSAkey k = DSA.PrivateKey
	(keyParam 'p' k, keyParam 'g' k, keyParam 'q' k) (keyParam 'x' k)

dsaKey :: OpenPGP.Packet -> DSA.PublicKey
dsaKey k = DSA.PublicKey
	(keyParam 'p' k, keyParam 'g' k, keyParam 'q' k) (keyParam 'y' k)

-- | Generate a key fingerprint from a PublicKeyPacket or SecretKeyPacket
-- <http://tools.ietf.org/html/rfc4880#section-12.2>
fingerprint :: OpenPGP.Packet -> String
fingerprint p
	| OpenPGP.version p == 4 = snd $ hash OpenPGP.SHA1 material
	| OpenPGP.version p `elem` [2, 3] = snd $ hash OpenPGP.MD5 material
	| otherwise = error "Unsupported Packet version or type in fingerprint"
	where
	material = LZ.concat $ OpenPGP.fingerprint_material p

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
			Left _ -> False
			Right v -> v
	rsaVerify =
		case RSA.verify bhash padding (rsaKey k) signature_over rsaSig of
			Left _ -> False
			Right v -> v
	rsaSig = toStrictBS $ LZ.drop 2 $ encode (head $ OpenPGP.signature sig)
	dsaSig = let [OpenPGP.MPI r, OpenPGP.MPI s] = OpenPGP.signature sig in
		(r, s)
	dsaTruncate (DSA.PublicKey (_,_,q) _) = BS.take (integerBytesize q)
	bhash = fst . hash hash_algo . toLazyBS
	padding = emsa_pkcs1_v1_5_hash_padding hash_algo
	hash_algo = OpenPGP.hash_algorithm sig
	signature_over = toStrictBS $ dta `LZ.append` OpenPGP.trailer sig
	Just k = OpenPGP.signature_issuer sig >>= find_key keys
	sig = sigs !! sigidx
	(sigs, (OpenPGP.LiteralDataPacket {OpenPGP.content = dta}):_) =
		OpenPGP.signatures_and_data message

-- | Sign data or key/userID pair.
sign :: (CryptoRandomGen g) =>
        OpenPGP.Message    -- ^ SecretKeys, one of which will be used
        -> OpenPGP.Message -- ^ Message containing data or key to sign, and optional signature packet
        -> OpenPGP.HashAlgorithm -- ^ HashAlgorithm to use in signature
        -> String  -- ^ KeyID of key to choose or @[]@ for first
        -> Integer -- ^ Timestamp for signature (unless sig supplied)
        -> g       -- ^ Random number generator
        -> OpenPGP.Packet
sign keys message hsh keyid timestamp g =
	-- WARNING: this style of update is unsafe on most fields
	-- it is safe on signature and hash_head, though
	sig {
		OpenPGP.signature = map OpenPGP.MPI final,
		OpenPGP.hash_head = 0 -- TODO
	}
	where
	final   = case OpenPGP.key_algorithm sig of
		OpenPGP.DSA -> [dsaR, dsaS]
		kalgo | kalgo `elem` [OpenPGP.RSA,OpenPGP.RSA_S] -> [toNum rsaFinal]
		      | otherwise ->
			error ("Unsupported key algorithm " ++ show kalgo ++ "in sign")
	Right ((dsaR,dsaS),_) = let k' = privateDSAkey k in
		DSA.sign g (dsaTruncate k' . bhash) k' dta
	Right rsaFinal = RSA.sign bhash padding (privateRSAkey k) dta
	dsaTruncate (DSA.PrivateKey (_,_,q) _) = BS.take (integerBytesize q)
	dta     = toStrictBS $ case signOver of {
		OpenPGP.LiteralDataPacket {OpenPGP.content = c} -> c;
		_ -> LZ.concat $ OpenPGP.fingerprint_material signOver ++ [
			LZ.singleton 0xB4,
			encode (fromIntegral (length firstUserID) :: Word32),
			LZ.fromString firstUserID
		]
	} `LZ.append` OpenPGP.trailer sig
	sig     = findSigOrDefault (find OpenPGP.isSignaturePacket m)
	padding = emsa_pkcs1_v1_5_hash_padding hsh
	bhash   = fst . hash hsh . toLazyBS
	toNum   = BS.foldl (\a b -> a `shiftL` 8 .|. fromIntegral b) 0

	-- Either a SignaturePacket was found, or we need to make one
	findSigOrDefault (Just s) =
		OpenPGP.signaturePacket
		(OpenPGP.version s)
		(OpenPGP.signature_type s)
		(OpenPGP.key_algorithm k) -- force to algo of key
		hsh -- force hash algorithm
		(OpenPGP.hashed_subpackets s)
		(OpenPGP.unhashed_subpackets s)
		(OpenPGP.hash_head s)
		(OpenPGP.signature s)
	findSigOrDefault Nothing  = OpenPGP.signaturePacket
		4
		defaultStype
		(OpenPGP.key_algorithm k) -- force to algo of key
		hsh
		([
			-- Do we really need to pass in timestamp just for the default?
			OpenPGP.SignatureCreationTimePacket $ fromIntegral timestamp,
			OpenPGP.IssuerPacket keyid'
		] ++ (case signOver of
			OpenPGP.LiteralDataPacket {} -> []
			_ -> [] -- TODO: OpenPGP.KeyFlagsPacket [0x01, 0x02]
		))
		[]
		undefined
		undefined

	keyid'  = reverse $ take 16 $ reverse $ fingerprint k
	Just k  = find_key keys keyid

	Just (OpenPGP.UserIDPacket firstUserID) = find isUserID m

	defaultStype = case signOver of
		OpenPGP.LiteralDataPacket {OpenPGP.format = f} ->
			if f == 'b' then 0x00 else 0x01
		_ -> 0x13

	Just signOver = find isSignable m
	OpenPGP.Message m = message

-- | Decrypt an OpenPGP message
--
-- TODO: verify MDC if present
decrypt ::
	OpenPGP.Message    -- ^ SecretKeys, one of which will be used
	-> OpenPGP.Message -- ^ An OpenPGP Message containing AssymetricSessionKey and EncryptedData
	-> Maybe OpenPGP.Message
decrypt keys msg@(OpenPGP.Message pkts) = do
	(_, d) <- getAsymmetricSessionKey keys msg
	pkt <- find isEncryptedData pkts
	decryptPacket d pkt

-- | Decrypt a single packet, given the decryptor
decryptPacket :: Decrypt -> OpenPGP.Packet -> Maybe OpenPGP.Message
decryptPacket d (OpenPGP.EncryptedDataPacket {
		OpenPGP.version = 1,
		OpenPGP.encrypted_data = encd
	}) | rechk == decode mdc = decode msg
	   | otherwise = Nothing
	where
	rechk = OpenPGP.ModificationDetectionCodePacket $ toLazyBS $ fst $
		hash OpenPGP.SHA1 $
		prefix `LZ.append` msg `LZ.append` LZ.pack [0xD3, 0x14]
	(msg,mdc) = LZ.splitAt (LZ.length content - 22) content
	(prefix, content) = d encd
decryptPacket _ (OpenPGP.EncryptedDataPacket {
		OpenPGP.version = 0
	}) = error "TODO: old-style encryption with no MDC in Data.OpenPGP.CryptoAPI.decryptPacket"
decryptPacket _ _ = error "Can only decrypt EncryptedDataPacket in Data.OpenPGP.CryptoAPI.decryptPacket"

-- | Decrypt a symmetric session key
getAsymmetricSessionKey ::
	OpenPGP.Message    -- ^ SecretKeys, one of which will be used
	-> OpenPGP.Message -- ^ An OpenPGP Message containing AssymetricSessionKey
	-> Maybe (OpenPGP.SymmetricAlgorithm, Decrypt)
getAsymmetricSessionKey keys (OpenPGP.Message ps) =
	listToMaybe $ mapMaybe decodeSessionKey $ catMaybes $
	concatMap (\(sk,ks) ->
		map ($ toStrictBS $ OpenPGP.encrypted_data sk) ks
	) toTry
	where
	toTry = map (id &&& lookupKey) sessionKeys

	lookupKey (OpenPGP.AsymmetricSessionKeyPacket {
		OpenPGP.key_algorithm = OpenPGP.RSA,
		OpenPGP.key_id = key_id
	}) | all (=='0') key_id = map (rsaDecrypt . snd) rsa
	   | otherwise = map (rsaDecrypt . snd) $
		filter (keyIdMatch key_id . fst) rsa
	lookupKey _ = []

	sessionKeys = filter isAsymmetricSessionKey ps
	(rsa, _) = secretKeys keys

decodeSessionKey :: BS.ByteString -> Maybe (OpenPGP.SymmetricAlgorithm, Decrypt)
decodeSessionKey sk
	| rechk == (decode (toLazyBS chk) :: Word16) = do
		algo <- maybeDecode (toLazyBS algoByte)
		decrypt <- decodeSymKey algo key
		return (algo, decrypt)
	| otherwise = Nothing
	where
	rechk = fromIntegral $
		BS.foldl' (\x y -> x + fromIntegral y) (0::Integer) key `mod` 65536
	(key, chk) = BS.splitAt (BS.length rest - 2) rest
	(algoByte, rest) = BS.splitAt 1 sk

decodeSymKey :: OpenPGP.SymmetricAlgorithm -> BS.ByteString -> Maybe Decrypt
decodeSymKey OpenPGP.AES128 k = pgpUnCFB <$> (`asTypeOf` (undefined :: AES128)) <$> sDecode k
decodeSymKey OpenPGP.AES192 k = pgpUnCFB <$> (`asTypeOf` (undefined :: AES192)) <$> sDecode k
decodeSymKey OpenPGP.AES256 k = pgpUnCFB <$> (`asTypeOf` (undefined :: AES256)) <$> sDecode k
decodeSymKey OpenPGP.Blowfish k = pgpUnCFB <$> (`asTypeOf` (undefined :: Blowfish)) <$> sDecode k
decodeSymKey _ _ = Nothing
