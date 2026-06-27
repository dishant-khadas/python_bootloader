This command is for display config of waveshare 7inch DSI LCD (C) 

open the file sudo nano /boot/firmware/config.txt and go to end of the file add these commands

dtoverlay=vc4-kms-v3d
#DSI1 Use
dtoverlay=vc4-kms-dsi-waveshare-panel,7_0_inchC,i2c1

After pasting the command reboot the raspi-4 using "sudo reboot" command