package edu.nku.AppReviewer;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class InstallReviewMetrics extends Activity{

	@Override
    public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
        setContentView(R.layout.metrics);
        
        //get parsed text and set it into the textview
        String text = getIntent().getStringExtra( "STRACE" );
        TextView tv = (TextView) findViewById( R.id.straceView );
        if( text != null )
        	tv.setText( text );
    	else
    		tv.setText( "FAIL" );
    }
}
