package edu.nku.AppReviewer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Environment;
import android.os.IBinder;
import android.util.Log;

public class InstallReview extends Service{
	
	private static final int HELLO_ID = 1;

	//start of the service to evaluate the strace.txt log for app install
	@Override
    public void onStart(Intent intent, int startId) {
		
		String packName = intent.getStringExtra( "INTENT" );
		//call method to parse log
		String[] log = parseText( packName );
		
		try {
			String[] words = packName.split( ":" );
			PrintWriter pw = new PrintWriter( new File( Environment.getExternalStorageDirectory(), words[1] + ".txt" ));
			pw.write( log[0] );
			pw.close();
			
			PrintWriter pw1 = new PrintWriter( new File( Environment.getExternalStorageDirectory(), words[1] + "Bad.txt" ));
			pw1.write( log[1] );
			pw1.close();
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//alert user that parsing has completed
		postNotification( packName, log[0] );
    }

	@Override
	public IBinder onBind(Intent arg0) {
		// TODO Auto-generated method stub
		return null;
	}
	
	//read the strace.txt log and select/label only the important information
	private String[] parseText( String intentString ){
		String parsedText = "";
		String unParsedText = "";
		String[] logs = new String[] { parsedText, unParsedText };
		String line;
		String nextLine = "";
		String prevLine = "";
		boolean header = false;
		boolean endReadWrite = false;
		boolean runUG = false;
		boolean jarHeader = false;
		boolean libsHeader = false;
		boolean sysHeader = false;
		String[] words = intentString.split( ":" );
		String packName = words[1];
		try {
			
			//create the reader
			BufferedReader br = new BufferedReader( new InputStreamReader( new FileInputStream ( new File( getFilesDir(), "strace.txt" )), "ISO-8859-1" ));
			line = br.readLine();
			
			//read through the entire file
			while( line != null ){
				
				//ignore lines of little significance
				if( !line.matches( ".*mprotect.*") && !line.matches( ".*mmap.*") && !line.matches( ".*sigaction.*") && !line.matches( ".*lseek.*" ) ){
					
					//check if APK was opened
					if( line.matches( ".*open\\(\"/data/app/.*")){
						parsedText += "\n#OPEN APK\n" + line + "\n";
					}
					
					//check if the DEX optimizer was opened
					else if( line.matches( ".*open\\(\"/data/dalvik-cache.*" )){
						parsedText += "\n#OPEN DEX\n" + line + "\n";
					}
					
					//check if making a directory
					else if(  line.matches( ".*mkdir\\(.*" ) )
						
						//check if directory was removed and recreated signifying that the dir is now to be for the app
						if( prevLine.matches( ".*rmdir\\(.*" )){
							nextLine = br.readLine();
							
							//get all important lines
							if( nextLine != null && nextLine.matches( ".* chown.*" ) ){
								parsedText += "\n#USER OPENS APP DIR\n" + prevLine + "\n" + line + "\n" + nextLine + "\n";
							}
							else{
								parsedText += "\n#USER OPENS APP DIR\n" + prevLine + "\n" + line + "\n";
								prevLine = line;
								line = nextLine;
							}
						}
					
						//directory must belong to the root
						else{
							
							//get required lines
							if( prevLine.matches( ".*read.*" ) )
								parsedText += "#ROOT OPENS APP DIR\n" + line + "\n";
							else{
								nextLine = br.readLine();
								if( nextLine != null && nextLine.matches( ".* chown.*" ) ){
									parsedText += prevLine + "\n" + line + "\n" + nextLine + "\n";
									prevLine = line;
									line = nextLine;
								}
							}
						}
					
					//check if forking for subprocess
					else if( line.matches( ".*fork\\(\\).*" )){
						nextLine = br.readLine();
						
						if( nextLine != null ){
							parsedText += "\n#FORK AS NON-ROOT\n" + prevLine + "\n" + line + "\n" + nextLine + "\n";
							
						}
						else{
							parsedText += "\n#FORK AS NON-ROOT\n" + prevLine + "\n" + line + "\n";
						}
						prevLine = line;
						line = nextLine;
					}
					
					//check if closing the file handler and dalvik cache
					else if( line.matches( ".*close\\(.*" ) && prevLine.matches( ".*close\\(.*")){
						parsedText += "\n#CLOSE FILEHANDLER AND DALVIK CACHE\n" + prevLine + "\n" + line + "\n";
						endReadWrite = true;
					}
					
					//check if opening lib as user
					else if( line.matches( ".*chown32\\(.*")){
						if( prevLine.matches( ".*chmod\\(.*" )){
							parsedText += "\n#OPEN LIB AND CHOWN TO USER\n" + prevLine + "\n" + line + "\n";
						}
					}
					
					//check if Directory Lockdown is occuring
					else if( line.matches( ".*chmod\\(\"/data/data/" + packName + "\", 0700\\).*" )){
						parsedText += "\n#LOCKING DOWN OUR DIRECTORY\n" + line + "\n";
					}
					
					//read/write to filehandlers opened at beginning of strace
					else if( endReadWrite ){
						if( !header ){
							parsedText += "\n#READ/WRITE TO FILEHANDLERS\n";
							header = true;
						}
						if( !line.matches( ".*unfinished.*" )){
							parsedText += line + "\n";
						}
					}
					
					//check for file handler write
					else if( line.matches( ".*DexInv: --- END.*" )){
						parsedText += "\nWRITE TO FILEHANDLER\n" + line + "\n";
					}
					
					//check if backing out to original process
					else if( line.matches( ".*SIGCHLD.*" )){
						if( prevLine.matches( ".*WIFEXITED\\(s\\) && WEXITSTATUS\\(s\\) == 0.*" )){
							parsedText += "\n#BACK TO ORIGINAL PROCESS\n" + prevLine + "\n" + line + "\n";
						}
					}
					
					//check for accounting
					else if( line.matches( ".*open\\(\"/acct/uid/0/tasks.*" )){
						parsedText += "\n#ACCOUNTING\n" + line + "\n";
						line = br.readLine();
						while( line != null && !line.matches( ".*open\\(\"/acct/uid/[0-9]{1,}/tasks.*" )){
							line = br.readLine();
						}
						if( line != null ){
							parsedText += line + "\n";
						}
					}
					
					//check for executable swap
					else if( line.matches( ".*execve\\(\"/system/bin/dexopt\".*" )){
						parsedText += "\n#DEX FOR EX\n" + line + "\n";
					}
					
					//check if we just did a lot of reads
					else if( line.matches( ".*wait4 resumed> \\[\\{WIFEXITED\\(s\\) && WEXITSTATUS.*" )){
						if( prevLine.matches( ".*SYS.*" )){
							parsedText += "\n#LOTS OF READS AND WRITES\n" + line + "\n";
						}
					}
					
					//check if subprocess is running as root
					else if( line.matches( ".*getuid32\\(\\)\\s+= 0.*" )){
						parsedText += "\n#SUBPROCESS AS ROOT\n" + line + "\n";
					}
					
					//check for running with UID/GID of new app
					else if( line.matches( ".*getuid32\\(\\)\\s+=.*" ) && !runUG ){
						parsedText += "\n#RUNING AS UID/GID\n" + line + "\n";
						while( ( line = br.readLine()) != null && line.matches( ".*get.*" )){
							parsedText += line + "\n";
						}
						runUG = true;
					}
					
					//opening system jars
					else if( line.matches( ".*open\\(\"/system/.*\\.jar\", O_RDONLY.*" )){
						if( !jarHeader ){
							parsedText += "\n#OPENING SYSTEM JARS\n" + line + "\n";
							jarHeader = true;
						}
						else{
							parsedText += line + "\n";
						}
					}
					
					//accessing the vendor/system libs
					else if( line.matches( ".*stat64\\(.*\\.so\".*" )){
						if( !libsHeader ){
							parsedText += "\n#Attempt to use vendor specific SSL and crypto libs\n" + line + "\n";
							libsHeader = true;
						}
						else{
							parsedText += line + "\n";
						}
					}
					else if( line.matches( ".*open\\(.*\\.so\".*" )){
						if( !sysHeader ){
							parsedText += "\n#Opening system Libs\n" + line + "\n";
							sysHeader = true;
						}
						else{
							parsedText += line + "\n";
						}
					}
					else{
						unParsedText += line + "\n";
					}
				}
				
				//move on to next line in the file
				prevLine = line;
				line = br.readLine();
			}
			
			//close the file reader
			br.close();
		} 
		
		//catch exceptions
        catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		logs[0] = parsedText;
		logs[1] = unParsedText;
		//return the parsed text
		return logs;
	}
	
	//alert the user that parsing is done and wait for them to react
	private void postNotification( String text, String log ){
		Log.d("NOTIFY", "NOTIFY");
		//get context and package name
		Context context = getApplicationContext();
		String[] words = text.split( ":" );
		
		//get notification service and create a notification manager
		String ns = Context.NOTIFICATION_SERVICE;
		NotificationManager mNotificationManager = (NotificationManager) context.getSystemService(ns);
		
		//set up notification information
		int icon = android.R.drawable.stat_sys_download_done;        // icon from resources
		CharSequence tickerText = "New app installed, click to review";              // ticker-text
		long when = System.currentTimeMillis();         // notification time
		CharSequence contentTitle = words[1];  // message title
		CharSequence contentText = "There is a new app to review";      // message text

		//create the intent the notification will use
		Intent notificationIntent = new Intent( context, InstallReviewMetrics.class );
		notificationIntent.putExtra( "STRACE", log );
		PendingIntent contentIntent = PendingIntent.getActivity( context, 0, notificationIntent, PendingIntent.FLAG_UPDATE_CURRENT);

		//initialize the Notification, using the configurations above
		Notification notification = new Notification(icon, tickerText, when);
		notification.defaults |= Notification.DEFAULT_SOUND;
		notification.flags = Notification.FLAG_AUTO_CANCEL;
		notification.setLatestEventInfo(context, contentTitle, contentText, contentIntent);
		
		//post notification
		mNotificationManager.notify(HELLO_ID, notification);
	}
}
