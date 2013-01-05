import System.Environment (getArgs)

import Data.Binary

import qualified Data.OpenPGP as OpenPGP
import qualified Data.OpenPGP.CryptoAPI as OpenPGP

main :: IO ()
main = do
	[keyPath, messagePath] <- getArgs
	keys <- decodeFile keyPath
	message <- decodeFile messagePath
	-- Just verify first signature
	let verified = OpenPGP.verify keys (head $ OpenPGP.signatures message)
	print $ 1 == length (OpenPGP.signatures_over verified)
