Import("env")
import os

if os.path.isfile('BTPatcher.py'):
    from BTPatcher import patch_esp32

    def run_patch(target, source, env):
        patch_esp32(str(target[0]))

    env.AddPostAction("$BUILD_DIR/${PROGNAME}.elf", [run_patch])


def before_upload(target, source, env):
    do_reset = env.GetProjectOption(
        "reset_before_after_flash", default='false')
    if 'true' in do_reset:
        monitor_port = env.GetProjectOption("monitor_port", default=None)
        if monitor_port:
            try:
                reset_firmware(monitor_port)
            except Exception as err:
                print(err)


def after_upload(target, source, env):
    do_reset = env.GetProjectOption(
        "reset_before_after_flash", default='false')
    if 'true' in do_reset:
        monitor_port = env.GetProjectOption("monitor_port", default=None)
        if monitor_port:
            try:
                reset_firmware(monitor_port)
            except Exception as err:
                print(err)


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


env.AddPreAction("upload", [before_upload])
env.AddPostAction("upload", [after_upload])
