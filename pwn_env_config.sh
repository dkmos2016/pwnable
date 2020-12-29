
sudo apt install git vim python python-pip libc-dbg:i386
cd ~ && mkdir -p .gdb pwnable/libcs Workspace 
cd Workspace && git clone https://github.com/dkmos2016/pwnable
cd .gdb
git clone https://github.com/dkmos2016/peda
git clone https://github.com/scwuaptx/Pwngdb
cp Pwngdb/.gdbinit ~/.gdbinit
sed -i 's/~\//~\/.gdb\//g' ~/.gdbinit



# setting env to change glibc 
git clone git clone git://sourceware.org/git/glibc.git
