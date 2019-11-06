sc stop HyperViper
sc delete HyperViper
sc create HyperViper binPath= %cd%\HyperViper.sys  type= kernel
sc start HyperViper