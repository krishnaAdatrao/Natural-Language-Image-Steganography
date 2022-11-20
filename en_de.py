from PIL import Image
import os
from os import path as OS_Route
from Crypto.Cipher import AES as adv_en
from Crypto.Hash import SHA256 as hashing
from Crypto import Random as ZigZag
import base64 as B64
from rich import print
from rich.console import Console as con
import getpass as gp
import sys


headerText = "M6nMjy5THr2J"


def text_ency(hash_rep, initiation):
    hash_rep = hashing.new(hash_rep).digest()  
    AES_en = ZigZag.new().read(adv_en.block_size)  
    enc = adv_en.new(hash_rep, adv_en.MODE_CBC, AES_en)
    block_rep = adv_en.block_size - len(initiation) % adv_en.block_size  
    initiation += bytes([block_rep]) * block_rep  
    raw_text = AES_en + enc.encrypt(initiation)  # encryption
    return B64.b64encode(raw_text).decode() if True else raw_text

def text_decy(hash_rep, initiation):
    if True:initiation = B64.b64decode(initiation.encode())
    hash_rep = hashing.new(hash_rep).digest()  
    AES_en = initiation[:adv_en.block_size]  
    dec = adv_en.new(hash_rep, adv_en.MODE_CBC, AES_en)
    raw_text = dec.decrypt(initiation[adv_en.block_size:])  # decryption
    block_rep = raw_text[-1]  
    if raw_text[-block_rep:] != bytes([block_rep]) * block_rep:  
        raise ValueError("Invalid block_rep...")
    return raw_text[:-block_rep]  

def Color_Conversion(Pic):
	try:
		Picture = Pic
		Picture.load()
		coloring = Image.new("RGB", Picture.size, (255, 255, 255))
		coloring.paste(Picture, mask = Picture.split()[3])
		print("[yellow]Converted image to RGB [/yellow]")
		return coloring
	except Exception as e:
		print("[red]Couldn't convert image to RGB [/red]- %s"%e)

def No_of_Pixels(Pic):
	breadth, length = Image.open(Pic).size
	return breadth*length



def Enc_Pic(image, textual_input, container):
	with con().status("[green]Encoding image..") as status:
		try:
			breadth, length = image.size
			pix = image.getdata()
			inp_pix, temporary, x, y = 0, 0, 0, 0
			
			for token in textual_input:
				
				combined_pix = [pix_transition for pix_transition in (pix[inp_pix]) + (pix[inp_pix + 1]) + (pix[inp_pix + 2])]

				for i in range(0,8):
					current_bit = format(ord(token), '08b')[i]
					if current_bit == '0': # 0 -> even
						if combined_pix[i] % 2 != 0:
							combined_pix[i] = combined_pix[i] - 1 if combined_pix[i]==255 else combined_pix[i] + 1
					elif current_bit == '1': # 1 -> odd
						if combined_pix[i] % 2 == 0:
							combined_pix[i] = combined_pix[i] - 1 if combined_pix[i] == 255 else combined_pix[i] + 1

				inp_pix += 3
				temporary += 1

				#Set 9th value
				if(temporary == len(textual_input)):
					# Make as 1 (odd) - stop reading
					if combined_pix[-1] % 2 == 0:
						combined_pix[-1] = combined_pix[-1] - 1 if combined_pix[-1] == 255 else combined_pix[-1] + 1
				else:
					# Make as 0 (even) - continue reading
					if combined_pix[-1] % 2 != 0:
						combined_pix[-1] = combined_pix[-1] - 1 if combined_pix[-1] == 255 else combined_pix[-1] + 1

				if False:
					print("\n", f'Token: {token}', "\n\n", "Binary: ",format(ord(token), '08b'), "\n\n", f'Three pixels before mod: {combined_pix}', "\n\n", f'Three pixels after mod: {combined_pix}')
				
				combined_pix = tuple(combined_pix)
				
				initial, final = 0, 3

				for i in range(0,3):
					if False:
						print("Putting pixel at ",(x,y)," to ",combined_pix[initial:final])

					image.putpixel((x,y), combined_pix[initial:final])
					initial += 3
					final += 3

					if (x == breadth - 1):
						x = 0
						y += 1
					else:
						x += 1

			encoded_container = container.split('.')[0] + "-stegano.png"
			image.save(encoded_container)
			print("\n")
			print("[yellow]Original File: [u]%s[/u][/yellow]"%container)
			print("[green]Image encoded and saved as [u][bold]%s[/green][/u][/bold]"%encoded_container)

		except Exception as e:
			print("[red]An error occured - [/red]%s"%e)
			sys.exit(0)



def Dec_Pic(image):
	with con().status("[green]Decoding image..") as status:
		try:
			pix = image.getdata()
			inp_pix = 0
			Decry_Text = ""

			while True:
				# Get 3 pixels each time
				base2 = ""
				combined_pix = [pix_transition for pix_transition in (pix[inp_pix]) + (pix[inp_pix + 1]) + (pix[inp_pix + 2])]

				for i in range(0,8):

					if combined_pix[i] % 2 == 0:
						
						base2 += "0" # add 0

					elif combined_pix[i] % 2 != 0:
						
						base2 += "1" # add 1


				#Convert binary value to ascii and add to string

				base2.strip()
				alphabetical = int(base2, 2)
				Decry_Text += chr(alphabetical)
				inp_pix += 3

				if False:
					print("\n\n", f'Binary: {base2}', "\n\n", f'Ascii: {alphabetical}', "\n\n", f'Character: {chr(alphabetical)}')

				if combined_pix[-1] % 2 != 0:
					# stop reading
					break

			return Decry_Text

		except Exception as e:
			print("[red]An error occured - [/red]%s"%e)
			sys.exit()

def main():
	user_selection = input("\nChoose one:\n\n1. Encryption\n2. Decryption\n>>").lower()

	if user_selection == "1" or user_selection == "encryption":
		print("[cyan]Image OS_Route (with extension): [/cyan]")
		Pic = input(">>")
		if(not(OS_Route.exists(Pic))):
			raise Exception("Image not found!")

		
		print("[cyan]textual_input to be hidden: [/cyan]")
		textual_input = input(">>")
		textual_input = headerText + textual_input
		if((len(textual_input)+len(headerText))*3 > No_of_Pixels(Pic)):
			raise Exception("GAES_enen textual_input is too long to be encoded in the image.")


		password=""
		while 1:
			print("[cyan]Password to encrypt (leave empty if you want no password): [/cyan]")
			password = gp.getpass(">>")
			if password=="":
				break
			print("[cyan]Re-enter Password: [/cyan]")
			confirm_password = gp.getpass(">>")
			if(password!=confirm_password):
				print("[red]Passwords don't match try again [/red]")
			else:
				break

		cipher=""
		if password!="":
			cipher = text_ency(hash_rep=password.encode(),initiation=textual_input.encode())
			# Add header to cipher
			cipher = headerText + cipher
		else:
			cipher = textual_input


		if False:
			print("[yellow]Encrypted : [/yellow]",cipher)

		image = Image.open(Pic)
		print("[yellow]Image Mode: [/yellow]%s"%image.mode)
		if image.mode!='RGB':
			image = Color_Conversion(image)
		newPic = image.copy()
		Enc_Pic(image=newPic,textual_input=cipher,container=image.filename)

	elif user_selection == "2" or user_selection == "decryption":
		print("[cyan]Image OS_Route (with extension): [/cyan]")
		Pic = input(">>")
		if(not(OS_Route.exists(Pic))):
			raise Exception("Image not found!")

		print("[cyan]Enter password (leave empty if no password): [/cyan]")
		password = gp.getpass(">>")

		image = Image.open(Pic)

		cipher = Dec_Pic(image)


		header = cipher[:len(headerText)]

		if header.strip()!=headerText:
			print("[red]Invalid data![/red]")
			sys.exit(0)


		print()

		if False:
			print("[yellow]Decrypted text: %s[/yellow]"%cipher)

		decrypted=""

		if password!="":
			cipher = cipher[len(headerText):]
			print("cipher : ",cipher)
			try:
				decrypted = text_decy(hash_rep=password.encode(),initiation=cipher)
			except Exception as e:
				print("[red]Wrong password![/red]")
				sys.exit(0)

		else:
			decrypted=cipher


		header = decrypted.decode()[:len(headerText)]

		if header!=headerText:
			print("[red]Wrong password![/red]")
			sys.exit(0)

		decrypted = decrypted[len(headerText):]



		print("[green]Decrypted Text: \n[bold]%s[/bold][/green]"%decrypted)


if __name__ == "__main__":
	os.system('cls' if os.name == 'nt' else 'clear')
	
	main()