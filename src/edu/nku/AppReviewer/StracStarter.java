package edu.nku.AppReviewer;

import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import android.app.Activity;
import android.content.Intent;
import android.content.res.AssetManager;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

public class StracStarter extends Activity {
    /** Called when the activity is first created. */
	
	//global variables
	Process strace;
	File file;
	File readFile;
	
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        //copy over strace executables to files dir for running
        AssetManager am = getAssets();
        try {
        	File straceFile = new File(getFilesDir() + "/strace");
        	if(!straceFile.exists()){
        		InputStream is = am.open("strace");
				OutputStream out = openFileOutput("strace", MODE_WORLD_READABLE);
				byte[] buffer = new byte[1024];
				int count = 0;
				while((count = is.read(buffer)) > 0){
					out.write(buffer, 0, count);
				}
				straceFile.setExecutable(true);
				is.close();
				out.close();
				Log.d("WROTE", "WROTE");
        	}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
        //create the files
        file = new File( getFilesDir(), "strace.sh" );
        readFile = new File( getFilesDir(), "strace.txt" );
    }
    
    //Method for when the start button was clicked
    public void onStartBtn( View v ){
    	
    	//delete the stracefile if it exists
    	readFile.delete();
		
    	//create variables
    	String pid = "";
        String line = "";
    	try {
    		
    		//get installd daemon
    		Process ps = Runtime.getRuntime().exec( "ps" );
			DataInputStream dIn = new DataInputStream( ps.getInputStream() );
			try {
				
				//wait for the process to complete
				ps.waitFor();
				
				//make sure process didn't exit badly
				if( ps.exitValue() != 255 ){
					
					//read lines from the process stream
					while( (line = dIn.readLine()) != null ){
						
						//check and find the installd daemon
						if( line.matches( ".*installd" )){
		            		String[] getPid = line.split( "\\s+" );
							pid = "" + getPid[1];
						}
					}
				}
				
				//no installd daemon exists
				else{
					pid = "NO installd";
				}
				
				//display what the daemon's ID is
				TextView tv = (TextView) findViewById( R.id.tv );
	            tv.setText( pid );
			} 
			catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			//close the stream reader if it exists
			if( dIn != null)
				dIn.close();
		} 
    	catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
    	//validate that the pid is numeric
    	if( isPID( pid ) ){
            try {
            	
            	//open a writer to write the strace.sh file
				BufferedWriter bw = new BufferedWriter( new FileWriter( file ));
				bw.write( "#!/system/bin/sh\n\n" );
				bw.write( "strace -f -p " + pid + " -o " + readFile.getAbsolutePath() + "\n" );
				bw.close();
				
				//make file executable
				file.setExecutable( true );
			} 
            catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
            try{
            	
            	//get root access and run the strace.sh file we created
    			strace = Runtime.getRuntime().exec( "su" );
    			DataOutputStream dOut = new DataOutputStream( strace.getOutputStream() );
    			dOut.writeBytes( file.getAbsolutePath() );
    			dOut.flush();
    			dOut.close();
    		}
    		catch( IOException e ){
    			e.printStackTrace();
    		}
        }
    }
    
    //method for when canceling strace
    public void onCancelStrace( View v ){
		
    	//get create the variables
    	String pid = "";
		String line;
		Process kill;
		
		try {
			//get the process id of strace
			kill = Runtime.getRuntime().exec( "ps" );
			
			//get the stream for reading
			DataInputStream dIn = new DataInputStream( kill.getInputStream() );
			try {
				
				//wait for process to finish
				kill.waitFor();
				
				//verify that the process wasn't terminated
				if( kill.exitValue() != 255 ){
					try {
						//read the lines from the stream
						while( (line = dIn.readLine()) != null ){
							
							//check if strace is running
							if( line.matches( ".*strace" )){
								
								//split line and get process id for strace
								String[] getPid = line.split( "\\s+" );
								pid = "" + getPid[1];
								
								//check the the PID is valid and kill it
								if( isPID( pid ) ){
									
									//kill strace
									Process pr = Runtime.getRuntime().exec( "su" );
									DataOutputStream dOut = new DataOutputStream( pr.getOutputStream() );
					    			dOut.writeBytes( "kill " + pid );
					    			dOut.flush();
					    			dOut.close();
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
		
		//delete file
		boolean deleted = readFile.delete();
		
		//update screen to show if file and process were terminated
		TextView tv = (TextView) findViewById( R.id.tv );
		tv.setText( "" + deleted );
   }
    
    public void loadManager( View v ){
    	Intent startManager = new Intent( android.provider.Settings.ACTION_MANAGE_APPLICATIONS_SETTINGS );
    	startActivity( startManager );
    }
   
    
   //check if the PID is numeric
   private boolean isPID(String pid) {
	   	try {
	   		Integer.parseInt(pid);
	   		return true;
	   	}
	   	catch (NumberFormatException e) {
	   		// s is not numeric
	   		return false;
	   	}
	}
}