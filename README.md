InstallReviewer
===============

Download and install instructions

Prerequisites
	1) Android SDK installed and android version 2.3.3 downloaded
	2) the Android SDK folders in your PATH: 
		A) export /PATH/TO/ANDROID/SDK/tools/
		B) export /PATH/TO/ANDROID/SDK/platform-tools/
	3) ant 1.7 or later
	4) only 1 connected android device or running emulator
	
INSTRUCTIONS
	1) git clone git://github.com/leibreichb1/InstallReviewer.git InstallReviewer
	2) cd InstallReviewer
	3) android update project --target android-10 --path . --name InstallReviewer
	3) cd bin
	4) adb install InstallReviewer-debug.apk