import Test.Framework (defaultMain, testGroup, Test)
import Test.Framework.Providers.HUnit
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck
import Test.QuickCheck.Instances ()
import Test.HUnit hiding (Test)

import Data.Maybe
import Data.Monoid
import Data.List (find)
import Crypto.Random
import Data.Binary
import Data.Bits (xor)
import qualified Data.OpenPGP as OpenPGP
import qualified Data.OpenPGP.CryptoAPI as OpenPGP
import qualified Data.ByteString.Lazy as LZ
import qualified Data.ByteString.Lazy.UTF8 as LZ (fromString, toString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.UTF8 as BS (fromString)

instance Arbitrary OpenPGP.HashAlgorithm where
	arbitrary = elements [OpenPGP.MD5, OpenPGP.SHA1, OpenPGP.RIPEMD160, OpenPGP.SHA256, OpenPGP.SHA384, OpenPGP.SHA512, OpenPGP.SHA224]

instance Arbitrary OpenPGP.SymmetricAlgorithm where
	arbitrary = elements [OpenPGP.AES128, OpenPGP.AES192, OpenPGP.AES256, OpenPGP.Blowfish]

isLiteral :: OpenPGP.Packet -> Bool
isLiteral (OpenPGP.LiteralDataPacket {}) = True
isLiteral                              _ = False

modifyLiteralPacket :: OpenPGP.Packet -> OpenPGP.Packet
modifyLiteralPacket d@(OpenPGP.LiteralDataPacket { OpenPGP.content = cnt }) =
	d { OpenPGP.content = LZ.cons 0x00 $ LZ.map (xor 0xFF) cnt }
modifyLiteralPacket nonliteral = nonliteral

testFingerprint :: FilePath -> String -> Assertion
testFingerprint fp kf = do
	bs <- LZ.readFile $ "tests/data/" ++ fp
	let (OpenPGP.Message [packet]) = decode bs
	assertEqual ("for " ++ fp) kf (OpenPGP.fingerprint packet)

testVerifyMessage :: FilePath -> FilePath -> Assertion
testVerifyMessage keyring message = do
	keys <- fmap decode $ LZ.readFile $ "tests/data/" ++ keyring
	m <- fmap decode $ LZ.readFile $ "tests/data/" ++ message
	let OpenPGP.DataSignature _ ss =
		OpenPGP.verify keys (head $ OpenPGP.signatures m)
	assertEqual (keyring ++ " for " ++ message) 1 (length ss)

testVerifyModifiedMessage :: FilePath -> FilePath -> Assertion
testVerifyModifiedMessage keyring message = do
	keys <- fmap decode $ LZ.readFile $ "tests/data/" ++ keyring
	OpenPGP.Message m <- fmap decode $ LZ.readFile $ "tests/data/" ++ message
	let corrupt_message = OpenPGP.Message (map modifyLiteralPacket m)
	let OpenPGP.DataSignature _ ss =
		OpenPGP.verify keys (head $ OpenPGP.signatures corrupt_message)
	assertEqual (keyring ++ " for " ++ message) 0 (length ss)

testVerifyKey :: FilePath -> Int -> Assertion
testVerifyKey keyring count = do
	keys <- fmap decode $ LZ.readFile $ "tests/data/" ++ keyring
	let out = OpenPGP.verify keys (OpenPGP.signatures keys !! 1)
	assertEqual keyring count (length $ OpenPGP.signatures_over out)

testDecryptHello :: Assertion
testDecryptHello = do
	keys <- fmap decode $ LZ.readFile "tests/data/helloKey.gpg"
	m <- fmap decode $ LZ.readFile "tests/data/hello.gpg"
	let Just (OpenPGP.Message [OpenPGP.CompressedDataPacket {
			OpenPGP.message = OpenPGP.Message msg
		}]) = OpenPGP.decryptAsymmetric keys m
	let content = fmap (LZ.toString . OpenPGP.content) (find isLiteral msg)
	assertEqual "Decrypt hello" (Just "hello\n") content

testDecryptSymmetric :: String -> String -> FilePath -> Assertion
testDecryptSymmetric pass cnt file = do
	m <- fmap decode $ LZ.readFile $ "tests/data/" ++ file
	let Just (OpenPGP.Message [OpenPGP.CompressedDataPacket {
			OpenPGP.message = OpenPGP.Message msg
		}]) = OpenPGP.decryptSymmetric [BS.fromString pass] m
	let content = fmap (LZ.toString . OpenPGP.content) (find isLiteral msg)
	assertEqual "Decrypt symmetric" (Just cnt) content

testDecryptSecretKey :: String -> FilePath -> Assertion
testDecryptSecretKey pass file = do
	m <- fmap decode $ LZ.readFile $ "tests/data/" ++ file
	let d = OpenPGP.decryptSecretKey (BS.fromString pass) m
	assertEqual "Decrypt secret key" True (isJust d)

prop_sign_and_verify :: (CryptoRandomGen g) => OpenPGP.Message -> g -> OpenPGP.HashAlgorithm -> String -> String -> Gen Bool
prop_sign_and_verify secring g halgo filename msg = do
	keyid <- elements ["FEF8AFA0F661C3EE","7F69FA376B020509"]
	let m = OpenPGP.LiteralDataPacket {
			OpenPGP.format = 'u',
			OpenPGP.filename = filename,
			OpenPGP.timestamp = 12341234,
			OpenPGP.content = LZ.fromString msg
		}
	let (sig,_) = OpenPGP.sign secring (OpenPGP.DataSignature m [])
			halgo keyid 12341234 g
	let OpenPGP.DataSignature _ ss = OpenPGP.verify secring sig
	return (length ss == 1)

prop_encrypt_and_decrypt :: (CryptoRandomGen g) => OpenPGP.Message -> g -> BS.ByteString -> OpenPGP.SymmetricAlgorithm -> String -> String -> Bool
prop_encrypt_and_decrypt secring g pass algo filename msg =
	case (OpenPGP.encrypt [] secring algo m g, OpenPGP.encrypt [pass] mempty algo m g) of
		(Left _, _) -> False
		(_, Left _) -> False
		(Right (encA, _), Right (encB, _)) ->
			(OpenPGP.decryptAsymmetric secring encA == Just m) &&
			(OpenPGP.decryptSymmetric [pass] encB == Just m)
	where
	m = OpenPGP.Message [OpenPGP.LiteralDataPacket {
			OpenPGP.format = 'u',
			OpenPGP.filename = filename,
			OpenPGP.timestamp = 12341234,
			OpenPGP.content = LZ.fromString msg
		}]

tests :: (CryptoRandomGen g) => OpenPGP.Message -> OpenPGP.Message -> g -> [Test]
tests secring oneKey rng =
	[
		testGroup "Fingerprint" [
			testCase "000001-006.public_key" (testFingerprint "000001-006.public_key" "421F28FEAAD222F856C8FFD5D4D54EA16F87040E"),
			testCase "000016-006.public_key" (testFingerprint "000016-006.public_key" "AF95E4D7BAC521EE9740BED75E9F1523413262DC"),
			testCase "000027-006.public_key" (testFingerprint "000027-006.public_key" "1EB20B2F5A5CC3BEAFD6E5CB7732CF988A63EA86"),
			testCase "000035-006.public_key" (testFingerprint "000035-006.public_key" "CB7933459F59C70DF1C3FBEEDEDC3ECF689AF56D")
		],
		testGroup "Message verification" [
			testCase "uncompressed-ops-dsa" (testVerifyMessage "pubring.gpg" "uncompressed-ops-dsa.gpg"),
			testCase "uncompressed-ops-dsa-sha384" (testVerifyMessage "pubring.gpg" "uncompressed-ops-dsa-sha384.txt.gpg"),
			testCase "uncompressed-ops-rsa" (testVerifyMessage "pubring.gpg" "uncompressed-ops-rsa.gpg"),
			testCase "compressedsig" (testVerifyMessage "pubring.gpg" "compressedsig.gpg"),
			testCase "compressedsig-zlib" (testVerifyMessage "pubring.gpg" "compressedsig-zlib.gpg"),
			testCase "compressedsig-bzip2" (testVerifyMessage "pubring.gpg" "compressedsig-bzip2.gpg"),
			testCase "corrupted-ops-dsa" (testVerifyModifiedMessage "pubring.gpg" "uncompressed-ops-dsa.gpg"),
			testCase "corrupted-ops-dsa-sha384" (testVerifyModifiedMessage "pubring.gpg" "uncompressed-ops-dsa-sha384.txt.gpg"),
			testCase "corrupted-ops-rsa" (testVerifyModifiedMessage "pubring.gpg" "uncompressed-ops-rsa.gpg")
		],
		testGroup "Key verification" [
			testCase "helloKey" (testVerifyKey "helloKey.gpg" 1)
		],
		testGroup "Signing" [
			testProperty "Signatures verify" (prop_sign_and_verify secring rng)
		],
		testGroup "Decryption" [
			testCase "decrypt hello" testDecryptHello,
			testCase "decrypt AES" (testDecryptSymmetric "hello" "PGP\n" "symmetric-aes.gpg"),
			testCase "decrypt session key" (testDecryptSymmetric "hello" "PGP\n" "symmetric-with-session-key.gpg"),
			testCase "decrypt Blowfish" (testDecryptSymmetric "hello" "PGP\n" "symmetric-blowfish.gpg"),
			testCase "decrypt no MDC" (testDecryptSymmetric "hello" "PGP\n" "symmetric-no-mdc.gpg"),
			testCase "decrypt secret key" (testDecryptSecretKey "hello" "encryptedSecretKey.gpg")
		],
		testGroup "Encryption" [
			testProperty "Encrypted messages decrypt" (prop_encrypt_and_decrypt oneKey rng)
		]
	]

main :: IO ()
main = do
	rng <- newGenIO :: IO SystemRandom
	secring <- fmap decode $ LZ.readFile "tests/data/secring.gpg"
	oneKey <- fmap decode $ LZ.readFile "tests/data/helloKey.gpg"
	defaultMain (tests secring oneKey rng)
