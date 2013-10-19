module Data.OpenPGP.CryptoAPI.Cryptocipher (Cryptocipher) where

import Crypto.Classes (BlockCipher(..))
import Data.ByteString (ByteString)
import Data.Tagged (Tagged(..), asTaggedTypeOf)
import qualified Crypto.Cipher.Types as Cryptocipher
import qualified Data.Serialize as Serialize

-- The key and an already-initialized context
data Cryptocipher a = Cryptocipher !a !ByteString

instance (Cryptocipher.Cipher a) => Serialize.Serialize (Cryptocipher a) where
	put (Cryptocipher _ k) = Serialize.putByteString k
	get = do
		bs <- Serialize.remaining >>= Serialize.getByteString
		case Cryptocipher.makeKey bs of
			Left x -> fail $ show x
			Right x -> return $ Cryptocipher (Cryptocipher.cipherInit x) bs

instance (Cryptocipher.BlockCipher a) => BlockCipher (Cryptocipher a) where
	blockSize = tagged
		where
		tagged = Tagged (Cryptocipher.blockSize witness * 8)
		Cryptocipher witness _ = (undefined `asTaggedTypeOf` tagged)
	encryptBlock (Cryptocipher ctx _) = Cryptocipher.ecbEncrypt ctx
	decryptBlock (Cryptocipher ctx _) = Cryptocipher.ecbDecrypt ctx
	buildKey bs = case Cryptocipher.makeKey bs of
		Left _ -> Nothing
		Right x -> Just $ Cryptocipher (Cryptocipher.cipherInit x) bs
	keyLength = tagged
		where
		tagged = Tagged (siz * 8)
		Cryptocipher.KeySizeFixed siz = Cryptocipher.cipherKeySize witness
		Cryptocipher witness _ = (undefined `asTaggedTypeOf` tagged)
