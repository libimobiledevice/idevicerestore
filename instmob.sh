brew install libusbmuxd
brew install automake
brew install --HEAD libimobiledevice
brew install cython
brew install gnutls
brew install libgcrypt
brew install libzip

printf  "\033[1;33m<!>\033[1;31m dependencies installed\033[1;33m<!>\033[0m\n"

cd ~/Library/Caches/Homebrew/libimobiledevice--git

printf  "\033[1;33m<!>\033[1;31m INSTALLING LIBIMOBILEDEVICE USING GNUTLS\033[1;33m<!>\033[0m\n"printf "{YW}<!>{LR}INSTALLING LIBIMOBILEDEVICE WITH GNUTLS..{YW}<!>{NC}\n"

./autogen.sh --disable-openssl
make
sudo make install


cd .. 
printf  "\033[1;33m<!>\033[1;31m CLONING IDEVICERESTORE \033[1;33m<!>\033[0m\n"

git clone https://github.com/libimobiledevice/idevicerestore
cd idevicerestore

printf "{YW}<!> {LR}installing idevicerestore{YW} <!>{NC}\n"
./autogen.sh
make
sudo make install

printf "\033[1;35m<!> Installation COMPLETE <!>\033[0m\n"
