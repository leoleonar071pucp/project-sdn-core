#!/usr/bin/env python3
import subprocess
import re

def test_radclient():
    rad_input = "User-Name=20192434,User-Password=pass_teleco123,NAS-IP-Address=127.0.0.1,NAS-Port=0"
    
    cmd = f'echo "{rad_input}" | radclient -x 127.0.0.1:1812 auth testing123'
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        output = result.stdout + result.stderr
        print("=== SALIDA DE radclient ===")
        print(output)
        
        if "Access-Accept" in output:
            # Extraer Filter-Id
            match = re.search(r'Filter-Id = "([^"]+)"', output)
            rol = match.group(1) if match else None
            print(f"✅ Autenticación exitosa, Rol: {rol}")
            return True, rol
        else:
            print("❌ Autenticación fallida")
            return False, None
    except Exception as e:
        print(f"Error: {e}")
        return False, None

if __name__ == "__main__":
    test_radclient()
