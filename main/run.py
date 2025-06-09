from flask import Flask, request, render_template, send_file
import os

app = Flask(__name__)

from PIL import Image
from sys import exit
import wave
import numpy as np
from cryptography.fernet import Fernet

key=""

def new_key():
    try:
        key=Fernet.generate_key()
        return key
    except:
        print("ERROR")

def encrypt(plain):
    try:
        f=Fernet(key)
        plain=plain.encode('ASCII')
        cipher=f.encrypt(plain)
        return cipher
    except:
        print("ERROR")

def decrypt(cipher):
    try:
        f=Fernet(key)
        text=f.decrypt(cipher)
        return text
    except:
        print("ERROR")

def hide_image(cover_path, secret_path, output_path):
    cover_image = Image.open(cover_path)
    secret_image = Image.open(secret_path)

    if cover_image.size[0] < secret_image.size[0] or cover_image.size[1] < secret_image.size[1]:
        raise ValueError("Cover image is too small to hold the secret image")

    cover_image = cover_image.convert("RGBA")
    secret_image = secret_image.convert("RGBA")

    cover_pixels = cover_image.load()
    secret_pixels = secret_image.load()

    for y in range(secret_image.size[1]):
        for x in range(secret_image.size[0]):
            cover_pixel = cover_pixels[x, y]
            secret_pixel = secret_pixels[x, y]

            new_pixel = (
                (cover_pixel[0] & 0xFE) | (secret_pixel[0] >> 7),
                (cover_pixel[1] & 0xFE) | (secret_pixel[1] >> 7),
                (cover_pixel[2] & 0xFE) | (secret_pixel[2] >> 7),
                cover_pixel[3]
            )

            cover_pixels[x, y] = new_pixel

    cover_image.save(output_path, "PNG")

def reveal_image(stego_image_path, output_path, size):
    stego_image = Image.open(stego_image_path)
    stego_image = stego_image.convert("RGBA")

    revealed_image = Image.new("RGBA", size)
    revealed_pixels = revealed_image.load()
    stego_pixels = stego_image.load()

    for y in range(size[1]):
        for x in range(size[0]):
            stego_pixel = stego_pixels[x, y]

            revealed_pixel = (
                (stego_pixel[0] & 1) << 7,
                (stego_pixel[1] & 1) << 7,
                (stego_pixel[2] & 1) << 7,
                255
            )

            revealed_pixels[x, y] = revealed_pixel

    revealed_image.save(output_path, "PNG")

def hide_text_in_image(cover_path, text, output_path):
    cover_image = Image.open(cover_path)
    cover_image = cover_image.convert("RGBA")
    cover_pixels = cover_image.load()

    text_binary = ''.join(format(ord(char), '08b') for char in text)
    text_len = len(text_binary)

    if cover_image.size[0] * cover_image.size[1] * 3 < text_len:
        raise ValueError("Cover image is too small to hold the secret text")

    index = 0
    for y in range(cover_image.size[1]):
        for x in range(cover_image.size[0]):
            cover_pixel = cover_pixels[x, y]

            if index < text_len:
                new_pixel = (
                    (cover_pixel[0] & 0xFE) | int(text_binary[index]),
                    cover_pixel[1],
                    cover_pixel[2],
                    cover_pixel[3]
                )
                index += 1
            else:
                new_pixel = cover_pixel

            if index < text_len:
                new_pixel = (
                    new_pixel[0],
                    (cover_pixel[1] & 0xFE) | int(text_binary[index]),
                    new_pixel[2],
                    new_pixel[3]
                )
                index += 1

            if index < text_len:
                new_pixel = (
                    new_pixel[0],
                    new_pixel[1],
                    (cover_pixel[2] & 0xFE) | int(text_binary[index]),
                    new_pixel[3]
                )
                index += 1

            cover_pixels[x, y] = new_pixel

    cover_image.save(output_path, "PNG")

def unhide_text_in_image(stego_image_path):
    stego_image = Image.open(stego_image_path)
    stego_image = stego_image.convert("RGBA")
    stego_pixels = stego_image.load()

    binary_data = ""
    for y in range(stego_image.size[1]):
        for x in range(stego_image.size[0]):
            stego_pixel = stego_pixels[x, y]
            binary_data += str(stego_pixel[0] & 1)
            binary_data += str(stego_pixel[1] & 1)
            binary_data += str(stego_pixel[2] & 1)

    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded_text = ""
    for byte in all_bytes:
        decoded_text += chr(int(byte, 2))
        if decoded_text.endswith("###"):
            break

    if "###" in decoded_text:
        return decoded_text.rstrip("###")
    else:
        return ""

def get_image_dimensions(image_path):
    with Image.open(image_path) as img:
        width, height = img.size
        return width, height

def hide_audio(secret_audio, cover_audio, output_audio):
    """
    Hides a secret audio file within a cover audio file and saves the resulting file.

    Parameters:
        secret_audio (str): The file path of the secret audio file.
        cover_audio (str): The file path of the cover audio file.
        output_audio (str): The file path to save the new audio file with hidden data.
    """
    # Open the secret and cover audio files
    with wave.open(secret_audio, 'rb') as secret, wave.open(cover_audio, 'rb') as cover:
        # Read frames as bytes
        cover_frames = np.frombuffer(cover.readframes(cover.getnframes()), dtype=np.int16)
        secret_frames = np.frombuffer(secret.readframes(secret.getnframes()), dtype=np.int16)

        # Check if the cover audio can accommodate the secret audio
        required_samples = len(secret_frames) * 16  # Each secret sample requires 16 bits
        if required_samples > len(cover_frames):
            raise ValueError("Cover audio is too short to hide the secret audio.")

        # Encode the secret audio into the cover audio
        cover_frames = cover_frames.copy()  # Create a writable copy
        for i, sample in enumerate(secret_frames):
            for bit_index in range(16):  # Encode 16 bits of each sample
                bit = (sample >> bit_index) & 1  # Extract the bit
                cover_index = i * 16 + bit_index  # Calculate the index in cover frames
                cover_frames[cover_index] &= ~1  # Clear the least significant bit
                cover_frames[cover_index] |= bit  # Set the LSB with the secret bit

        # Save the new audio file with the hidden data
        with wave.open(output_audio, 'wb') as output:
            output.setparams(cover.getparams())
            output.writeframes(cover_frames.tobytes())

    print(f"Secret audio hidden in '{output_audio}'.")

    with wave.open(secret_audio, 'rb') as secret:
        secret_audio_length = secret.getnframes()
        print("Secret audio length",secret_audio_length)

def unhide_audio(cover_audio, output_secret_audio, secret_audio_length):
    """
    Unhides a secret audio file from a cover audio file and saves it.

    Parameters:
        cover_audio (str): The file path of the cover audio file.
        output_secret_audio (str): The file path to save the extracted secret audio file.
        secret_audio_length (int): The number of frames (samples) in the secret audio.
    """
    # Open the cover audio file
    with wave.open(cover_audio, 'rb') as cover:
        # Read frames as bytes
        cover_frames = np.frombuffer(cover.readframes(cover.getnframes()), dtype=np.int16)

        # Prepare to extract the secret audio
        secret_frames = np.zeros(secret_audio_length, dtype=np.int16)
        for i in range(secret_audio_length):
            for bit_index in range(16):  # Decode 16 bits per sample
                cover_index = i * 16 + bit_index  # Calculate the index in cover frames
                bit = cover_frames[cover_index] & 1  # Extract the least significant bit
                secret_frames[i] |= (bit << bit_index)  # Add the bit to the secret frame

        # Save the extracted secret audio
        with wave.open(output_secret_audio, 'wb') as output:
            params = cover.getparams()
            output.setparams((1, 2, params.framerate, secret_audio_length, 'NONE', 'not compressed'))
            output.writeframes(secret_frames.tobytes())

    print(f"Secret audio extracted to '{output_secret_audio}'.")

def hide_text_in_audio(secret_text, cover_audio, output_audio):
    """
    Hides a secret text message within a cover audio file and saves the resulting file.

    Parameters:
        secret_text (str): The secret text to hide.
        cover_audio (str): The file path of the cover audio file.
        output_audio (str): The file path to save the new audio file with hidden text.
    """
    # Convert the secret text to a binary representation
    secret_binary = ''.join(format(ord(char), '08b') for char in secret_text) + '00000000'  # Add a null terminator
    secret_bits = list(map(int, secret_binary))  # Convert binary string to list of bits

    # Open the cover audio file
    with wave.open(cover_audio, 'rb') as cover:
        # Read frames as bytes
        cover_frames = np.frombuffer(cover.readframes(cover.getnframes()), dtype=np.int16)

        # Check if the cover audio can accommodate the secret text
        if len(secret_bits) > len(cover_frames):
            raise ValueError("Cover audio is too short to hide the secret text.")

        # Create a writable copy of the cover frames
        modified_frames = cover_frames.copy()

        # Embed the secret bits into the least significant bits of the audio
        for i, bit in enumerate(secret_bits):
            modified_frames[i] &= ~1  # Clear the least significant bit
            modified_frames[i] |= bit  # Set the LSB with the secret bit

        # Save the modified audio with the hidden text
        with wave.open(output_audio, 'wb') as output:
            output.setparams(cover.getparams())
            output.writeframes(modified_frames.tobytes())

    print(f"Secret text hidden in '{output_audio}'.")

def unhide_text_from_audio(cover_audio):
    """
    Extracts a hidden text message from a cover audio file. 
    Returns an empty string if no hidden text is found.

    Parameters:
        cover_audio (str): The file path of the cover audio file containing the hidden text.

    Returns:
        str: The extracted secret text or an empty string if no text is found.
    """
    # Open the cover audio file
    with wave.open(cover_audio, 'rb') as cover:
        # Read frames as bytes
        cover_frames = np.frombuffer(cover.readframes(cover.getnframes()), dtype=np.int16)

        # Extract the least significant bits (LSBs) from the cover audio frames
        bits = []
        for frame in cover_frames:
            bits.append(frame & 1)  # Extract the LSB

        # Convert the extracted bits into bytes
        secret_binary = ''.join(map(str, bits))
        secret_bytes = [secret_binary[i:i + 8] for i in range(0, len(secret_binary), 8)]

        # Decode the bytes into characters, stopping at the null terminator (00000000)
        secret_text = ''
        for byte in secret_bytes:
            if byte == '00000000':  # Null terminator indicates the end of the hidden text
                break
            secret_text += chr(int(byte, 2))  # Convert binary to character

        # If no text was found, return an empty string
        if secret_text == '':
            return ''

    return secret_text

def get_audio_length(audio_path):
    with wave.open(audio_path, 'rb') as secret:
        secret_audio_length = secret.getnframes()
        return("Secret audio length",secret_audio_length)

def encrypt_file(fn1,fn2):
    try:
        f=open(fn1,"r")
        s=str(f.read())
        f.close()
        s=str(encrypt(s),'utf-8')
        f=open(fn2,"w")
        f.write(s)
        f.close()
        print("\nFILE ENCRYPTED\n")
    except:
        error("ERROR")

def decrypt_file(fn1,fn2):
    try:
        f=open(fn1,"r")
        s=str(f.read())
        f.close()
        s=str(decrypt(s.encode('ASCII')),'utf-8')
        f=open(fn2,"w")
        f.write(s)
        f.close()
        print("\nFILE DECRYPTED\n")
    except:
        error("ERROR")

@app.route('/')
def index():
    return render_template('index.html')  # Create an HTML file for the homepage with links to each functionality

@app.route('/hide_image', methods=['GET', 'POST'])
def hide_image_ui():
    if request.method == 'POST':
        cover_path = request.files['cover_image']
        secret_path = request.files['secret_image']
        output_path = os.path.join('static','output.png')
        cover_path.save('static/temp_cover.png')
        secret_path.save('static/temp_secret.png')
        hide_image('static/temp_cover.png', 'static/temp_secret.png', output_path)
        return send_file(output_path, as_attachment=True)
    return render_template('hide_image.html')  # Create a form for uploading images

@app.route('/reveal_image', methods=['GET', 'POST'])
def reveal_image_ui():
    if request.method == 'POST':
        stego_image_path = request.files['stego_image']
        output_path = os.path.join('static','revealed_image.png')
        stego_image_path.save('static/temp_stego.png')
        width, height = get_image_dimensions('static/temp_stego.png')
        reveal_image('static/temp_stego.png', output_path, (width, height))
        return send_file(output_path, as_attachment=True)
    return render_template('reveal_image.html')  # Create a form for uploading the stego image

@app.route('/hide_text_in_image', methods=['GET', 'POST'])
def hide_text_in_image_ui():
    global key
    if request.method == 'POST':
        key = request.form['key'].encode('ASCII')
        cover_path = request.files['cover_image']
        text = request.form['text']
        output_path = os.path.join('static','output.png')
        try:
            text = str(encrypt(text), 'utf-8') + "###"
            cover_path.save('static/temp_cover.png')
            hide_text_in_image('static/temp_cover.png', text, output_path)
            return send_file(output_path, as_attachment=True)
        except:
            return render_template('invalid_key.html')
    return render_template('hide_text_in_image.html')  # Create a form for text and image input

@app.route('/unhide_text_in_image', methods=['GET', 'POST'])
def unhide_text_in_image_ui():
    global key
    if request.method == 'POST':
        key = request.form['key'].encode('ASCII')
        stego_image_path = request.files['stego_image']
        stego_image_path.save('static/temp_stego.png')
        hidden_text = unhide_text_in_image('static/temp_stego.png')
        try:
            if hidden_text=="":
                return f"No hidden text found."
            hidden_text = str(decrypt(hidden_text.encode('ASCII')), 'utf-8')
            return render_template('hidden_text.html',hidden_text=hidden_text)
        except:
            return render_template('invalid_key.html')
    return render_template('unhide_text_in_image.html')  # Create a form for the key and image input

@app.route('/hide_audio', methods=['GET', 'POST'])
def hide_audio_ui():
    secret_audio_length = None  # Initialize secret_audio_length
    if request.method == 'POST':
        secret_audio = request.files['secret_audio']
        cover_audio = request.files['cover_audio']
        output_audio = os.path.join('static','output_audio.wav')
        secret_audio.save('static/temp_secret_audio.wav')
        cover_audio.save('static/temp_cover_audio.wav')
        # Hide the audio
        hide_audio('static/temp_secret_audio.wav', 'static/temp_cover_audio.wav', output_audio)
        # Get the secret audio length (in frames)
        secret_audio_length = get_audio_length('static/temp_secret_audio.wav')[1]
        return render_template(
            'hide_audio.html', 
            success=True, 
            secret_audio_length=secret_audio_length, 
            output_audio=output_audio
        )
    return render_template('hide_audio.html', success=False)

@app.route('/reveal_audio', methods=['GET', 'POST'])
def reveal_audio_ui():
    if request.method == 'POST':
        stego_audio = request.files['stego_audio']
        secret_audio_length = int(request.form['secret_audio_length'])
        output_audio = os.path.join('static','revealed_audio.wav')
        stego_audio.save('static/temp_stego_audio.wav')
        unhide_audio('static/temp_stego_audio.wav', output_audio, secret_audio_length)
        return send_file(output_audio, as_attachment=True)
    return render_template('reveal_audio.html')  # Create a form for uploading the stego audio and inputting secret length

@app.route('/hide_text_in_audio', methods=['GET', 'POST'])
def hide_text_in_audio_ui():
    global key
    if request.method == 'POST':
        key = request.form['key'].encode('ASCII')
        cover_audio = request.files['cover_audio']
        secret_text = request.form['text']
        output_audio = os.path.join('static','output_audio.wav')
        try:
            secret_text = str(encrypt(secret_text), 'utf-8')
            cover_audio.save('static/temp_cover_audio.wav')
            hide_text_in_audio(secret_text, 'static/temp_cover_audio.wav', output_audio)
            return send_file(output_audio, as_attachment=True)
        except:
            return render_template('invalid_key.html')
    return render_template('hide_text_in_audio.html')  # Create a form for text input and audio upload

@app.route('/unhide_text_from_audio', methods=['GET', 'POST'])
def unhide_text_from_audio_ui():
    global key
    if request.method == 'POST':
        key = request.form['key'].encode('ASCII')
        stego_audio = request.files['stego_audio']
        stego_audio.save('static/temp_stego_audio.wav')
        hidden_text = unhide_text_from_audio('static/temp_stego_audio.wav')
        try:
            if hidden_text=='':
                return f"No hidden text found."
            hidden_text = str(decrypt(hidden_text.encode('ASCII')), 'utf-8')
            return render_template('hidden_text.html',hidden_text=hidden_text)
        except:
            return render_template('invalid_key.html')
    return render_template('unhide_text_from_audio.html')  # Create a form for the key and audio input

@app.route('/encrypt_file', methods=['GET', 'POST'])
def encrypt_file_ui():
    global key
    if request.method == 'POST':
        key = request.form['key'].encode('ASCII')
        input_file = request.files['input_file']
        output_file = os.path.join('static','encrypted_file.txt')
        input_file.save('static/temp_input.txt')
        try:
            encrypt_file('static/temp_input.txt', output_file)
            return send_file(output_file, as_attachment=True)
        except:
            return render_template('invalid_key.html')
    return render_template('encrypt_file.html')  # Create a form for uploading the text file and inputting the key

@app.route('/decrypt_file', methods=['GET', 'POST'])
def decrypt_file_ui():
    global key
    if request.method == 'POST':
        key = request.form['key'].encode('ASCII')
        input_file = request.files['input_file']
        output_file = os.path.join('static','decrypted_file.txt')
        input_file.save('static/temp_input.txt')
        try:
            decrypt_file('static/temp_input.txt', output_file)
            return send_file(output_file, as_attachment=True)
        except:
            return render_template('invalid_key.html')
    return render_template('decrypt_file.html')  # Create a form for uploading the text file and inputting the key

@app.route('/generate_key', methods=['GET','POST'])
def generate_key_ui():
    global key
    if request.method == 'POST':
        key = str(new_key(), 'utf-8')
        return render_template('generate_key.html',k=key)
    if(isinstance(key,bytes)):
        key = str(key, 'utf-8')
    return render_template('generate_key.html',k=key)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)