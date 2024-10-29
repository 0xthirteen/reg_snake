# reg_snake

Python tool that leverages Impacket to interact with registry using WMI StdRegProv.

Installation
```
pip install impacket
```


Basic usage
```
python reg_snake.py -command enumvalues -subkey "HKCU\SOFTWARE\Google\Chrome" ./admin:password@10.10.10.10
```

Like other Impacket tools, can use user/pass, hashes or kerberos for authentication. 
