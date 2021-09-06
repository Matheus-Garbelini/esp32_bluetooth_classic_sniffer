#!./runtime/install/bin/python3

import sys
import os
import subprocess
import shutil
import platform
from time import sleep
from pathlib import Path
from hashlib import sha1
from urllib.request import urlretrieve
from zipfile import ZipFile, ZIP_DEFLATED


args = sys.argv[1:]
system_name = platform.system()
is_linux = system_name == 'Linux' or system_name == 'Darwin'
firmware_path = sys.path[0] / Path('firmware')
pio_build_path = Path('.pio/build/esp32doit-devkit-v1-serial/')


def has_pio():
    if is_linux:
        find_cmd = 'which'
    else:
        find_cmd = 'where'

    result = subprocess.run(
        [find_cmd, 'pio'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode()
    if len(output) > 0 and result.returncode == 0:
        return output
    return None


def is_source_project():
    return os.path.isdir('src')


def get_platformio_version():
    result = subprocess.run(
        ['pio', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    return result.split(b' ')[-1].replace(b'\r', b'').replace(b'\n', b'')


def get_platformio_config_json():
    return subprocess.run(['pio', 'project', 'config', '--json-output'],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.replace(b'\r', b'').replace(b'\n', b'')


def generate_project_checksum():
    print('Generating project.checksum')
    # PIO Core version changes
    checksum = sha1(get_platformio_version())
    # Configuration file state
    checksum.update(get_platformio_config_json())
    # Write project checksum
    with open(Path('.pio/build/project.checksum'), 'w') as out:
        out.write(checksum.hexdigest())


def download_file(url, file_name):
    if os.path.isfile(file_name):
        return

    def ProgressBar(block_num, block_size, total_size):
        downloaded = block_num * block_size
        if downloaded < total_size:
            completed = round((downloaded * 100) / total_size, 2)
            sys.stdout.write('\r' + str(completed) + '%')
            sys.stdout.flush()
        else:
            print('\nDone')

    print('Downloading ' + file_name + '...')
    urlretrieve(url, file_name, reporthook=ProgressBar)


def reset_firmware(serial_port):
    try:
        import serial
    except:
        print("[ERROR] pyserial module not found, installing now via pip...")
        os.system(sys.executable + ' -m pip install pyserial --upgrade')
        os.sync()

    # We should have pyserial here
    import serial

    ser = serial.Serial(serial_port, 115200, rtscts=False, dsrdtr=False)
    ser.rts = True
    ser.dtr = True
    ser.dtr = False
    ser.dtr = True
    ser.close()
    ser = None
    print('Reset Done! EN pin toggled HIGH->LOW->HIGH')


def flash_firmware(serial_port):
    os.makedirs(pio_build_path, exist_ok=True)

    if not is_source_project():
        generate_project_checksum()
        shutil.copyfile('firmware.bin', pio_build_path / 'firmware.bin')
        shutil.copyfile('bootloader.bin', pio_build_path / 'bootloader.bin')
        shutil.copyfile('partitions.bin', pio_build_path / 'partitions.bin')
    elif not os.path.isfile(pio_build_path / 'firmware.bin'):
        print('[ERROR] Build project first. Example: ./firmware.py build')
        exit(1)

    print('Flashing firmware...')
    os.system('pio run -e esp32doit-devkit-v1-serial -v -t nobuild -t upload --upload-port ' +
              serial_port)


if __name__ == "__main__":
    # Change working dir to firmware path
    os.chdir(firmware_path)
    enable_build = is_source_project()
    home_path = str(Path.home())

    if is_linux:
        # Fix locale
        os.environ['LC_ALL'] = 'C.UTF-8'
        os.environ['LANG'] = 'C.UTF-8'

    if not has_pio():
        # Try adding platformio bin folder to path environment
        if is_linux:
            os.environ['PATH'] = home_path + \
                '/.platformio/penv/bin/:' + os.environ['PATH']
        elif platform.system() == 'Windows':
            os.environ['Path'] = home_path + \
                '\\.platformio\\penv\\Scripts;' + os.environ['Path']
        # install platformio if not present on system
        if not has_pio():
            print('Platformio not found, installing now...')
            download_file(
                'https://raw.githubusercontent.com/platformio/platformio-core-installer/master/get-platformio.py',
                'get-platformio.py')
            os.system(sys.executable + ' get-platformio.py')

    # Handle arguments
    if len(args):

        for i, arg in enumerate(args):
            if 'build' in arg and enable_build:
                print('Building firmware from source...')
                os.system('pio run -e esp32doit-devkit-v1-serial')
                os.makedirs('release', exist_ok=True)
                shutil.copyfile(pio_build_path / 'firmware.bin',
                                Path('release/firmware.bin'))
                shutil.copyfile(pio_build_path / 'bootloader.bin',
                                Path('release/bootloader.bin'))
                shutil.copyfile(pio_build_path / 'partitions.bin',
                                Path('release/partitions.bin'))
                shutil.copyfile('PlatformioScripts.py', Path(
                    'release/PlatformioScripts.py'))
                shutil.copyfile('platformio.ini', Path(
                    'release/platformio.ini'))
                shutil.copyfile('firmware.py', Path('release/firmware.py'))
                # Create a ZipFile Object
                with ZipFile(Path('release/esp32driver.zip'), 'w', ZIP_DEFLATED) as zipObj:
                    # Add multiple files to the zip
                    zipObj.write(Path('release/firmware.bin'))
                    zipObj.write(Path('release/bootloader.bin'))
                    zipObj.write(Path('release/partitions.bin'))
                    zipObj.write(Path('release/PlatformioScripts.py'))
                    zipObj.write(Path('release/platformio.ini'))
                    zipObj.write(Path('release/firmware.py'))
                exit(0)

            elif 'clean' in arg and enable_build:
                os.system('pio run -v -t clean')

            elif 'flash' in arg:
                if len(args) < i + 2:
                    print(
                        '[ERROR] Missing serial port argument. Example: ./firmware.py flash /dev/ttyUSB0')
                    exit(1)
                flash_firmware(args[i + 1])
                exit(0)

            elif 'reset' in arg:
                if len(args) < i + 2:
                    print(
                        '[ERROR] Missing serial port argument. Example: ./firmware.py flash /dev/ttyUSB0')
                    exit(1)
                reset_firmware(args[i + 1])
                exit(0)

    # Print usage
    print('------ Usage help -------')
    if enable_build:
        print('./firmware.py build              # Build firmware using platformio and distribute it to release folder')
        print('./firmware.py clean              # Clean firmware build files')
    print('./firmware.py flash <port name>  # Flash firmware using serial port')
    print('./firmware.py reset <port name>  # Reset firmware using serial port')
