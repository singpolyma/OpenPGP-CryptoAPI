module Data.OpenPGP.CryptoAPI.Blowfish128 (Blowfish128) where

import Crypto.Classes (BlockCipher(..))
import Data.ByteString (ByteString)
import Data.Tagged (Tagged(..))
import qualified Crypto.Cipher.Blowfish as Blowfish
import Crypto.Cipher.Types hiding (BlockCipher)
import qualified Data.Serialize as Serialize

-- The key and an already-initialized context
data Blowfish128 = Blowfish128 !Blowfish.Blowfish128 !ByteString

instance Serialize.Serialize Blowfish128 where
	put (Blowfish128 _ k) = Serialize.putByteString k
	get = do
		bs <- Serialize.remaining >>= Serialize.getByteString
		case makeKey bs of
			Left x -> fail $ show x
			Right x -> return $ Blowfish128 (cipherInit x) bs

instance BlockCipher Blowfish128 where
	blockSize = Tagged 64
	encryptBlock (Blowfish128 ctx _) = ecbEncrypt ctx
	decryptBlock (Blowfish128 ctx _) = ecbDecrypt ctx
	buildKey bs = case makeKey bs of
		Left _ -> Nothing
		Right x -> Just $ Blowfish128 (cipherInit x) bs
	keyLength = Tagged 128
