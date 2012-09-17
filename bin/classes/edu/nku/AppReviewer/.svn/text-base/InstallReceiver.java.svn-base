package edu.nku.AppReviewer;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public class InstallReceiver extends BroadcastReceiver{
	
	//reciever to kill the strace listener
	@Override
	public void onReceive( Context context, Intent intent ){
		//call a method to kill strace
		boolean running = killStrace();
		
		//only evaluate the install if strace was running
		if( running ){
			
			//launch the service to evaluate the log with the package name of app to be installed
			Intent installDone = new Intent( context, InstallReview.class );
			installDone.putExtra( "INTENT",  intent.getDataString() );
			context.startService( installDone );
		}
	}
	
	//method to check if strace is running and kill the process if it is
	private boolean killStrace(){
		
		//creating variables
		boolean running = false;
		String pid = "";
		String line;
		Process kill;
		try {
			
			//get executing processes with the name strace
			kill = Runtime.getRuntime().exec( "ps strace" );
			
			//read the stream for the strace process
			DataInputStream dIn = new DataInputStream( kill.getInputStream() );
			try {
				
				//wait for kill process to end
				kill.waitFor();
				
				//make sure process wasn't terminated
				if( kill.exitValue() != 255 ){
					try {
						
						//read all lines from stream
						while( (line = dIn.readLine()) != null ){
							
							//check if strace exists
							if( line.matches( ".*strace" )){
								
								//get processID
								String[] getPid = line.split( "\\s+" );
								pid = "" + getPid[1];
								
								//make sure we can get a process number
								if( isPID( pid ) ){
									
									//kill the strace process
									Process pr = Runtime.getRuntime().exec( "su" );
									DataOutputStream dOut = new DataOutputStream( pr.getOutputStream() );
					    			dOut.writeBytes( "kill " + pid );
					    			dOut.flush();
					    			dOut.close();
					    			
					    			//set found flag to true
					    			running = true;
								}
							}
						}
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			} 
			catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		//return if found or not
		return running;
	}
	
	//check that input is a number
	private boolean isPID(String pid) {
    	try {
    		
    		//validate number
    		Integer.parseInt(pid);
    		return true;
    	}
    	
    	//not a number
    	catch (NumberFormatException e) {
    		// s is not numeric
    		return false;
    	}
	}
}