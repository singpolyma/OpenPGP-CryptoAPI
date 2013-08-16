module Data.OpenPGP.CryptoAPI.Blowfish128 (Blowfish128) where

import Crypto.Classes (BlockCipher(..))
import Data.Tagged (Tagged(..))
import qualified Crypto.Cipher.Blowfish as Blowfish
import qualified Data.Serialize as Serialize

newtype Blowfish128 = Blowfish128 Blowfish.Blowfish

instance Serialize.Serialize Blowfish128 where
	put (Blowfish128 b) = Serialize.put b
	get = fmap Blowfish128 Serialize.get

instance BlockCipher Blowfish128 where
	blockSize = Tagged 64
	encryptBlock (Blowfish128 k) = Blowfish.encryptBlock k
	decryptBlock (Blowfish128 k) = Blowfish.decryptBlock k
	buildKey = fmap Blowfish128 . Blowfish.buildKey
	keyLength = Tagged 128
