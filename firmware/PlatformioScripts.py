Import("env")
import os
from firmware import reset_firmware

if os.path.isfile('BTPatcher.py'):
    from BTPatcher import patch_esp32


    def run_patch(target, source, env):
        patch_esp32(str(target[0]))


    env.AddPostAction("$BUILD_DIR/${PROGNAME}.elf", [run_patch])


def before_upload(target, source, env):
	do_reset = env.GetProjectOption("reset_before_after_flash", default='false')
	if 'true' in do_reset:
		monitor_port = env.GetProjectOption("monitor_port", default=None)
		if monitor_port:
			try:
				reset_firmware(monitor_port)
			except Exception as err:
				print(err)

def after_upload(target, source, env):
	do_reset = env.GetProjectOption("reset_before_after_flash", default='false')
	if 'true' in do_reset:
		monitor_port = env.GetProjectOption("monitor_port", default=None)
		if monitor_port:
			try:
				reset_firmware(monitor_port)
			except Exception as err:
				print(err)

env.AddPreAction("upload", [before_upload])
env.AddPostAction("upload", [after_upload])