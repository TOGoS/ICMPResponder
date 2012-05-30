package togos.icmpresponder;

import java.util.Random;

import togos.icmpresponder.packet.IPPacket;
import togos.icmpresponder.packet.TCPSegment;

/* Note: this code is incomplete (can't initiate connections or send data),
 * terrible, and won't handle resends properly and should be re-thought, but it
 * gets the job done in some limited cases */
public class TCPSession
{
	public final static int STATE_LISTEN       = 0;
	public final static int STATE_SYN_SENT     = 1;
	public final static int STATE_SYN_RECEIVED = 2;
	public final static int STATE_ESTABLISHED  = 3;
	public final static int STATE_FIN_WAIT_1   = 4;
	public final static int STATE_FIN_WAIT_2   = 5;
	public final static int STATE_CLOSE_WAIT   = 6;
	public final static int STATE_LAST_ACK     = 7;
	public final static int STATE_TIME_WAIT    = 8;
	public final static int STATE_CLOSED       = 9;
	
	protected int state = STATE_CLOSED;
	protected int incomingSequenceNumber;
	protected int outgoingSequenceNumber = new Random().nextInt();
	
	static class OutgoingPacket {
		final long sentAt;
		final IPPacket packet;
		
		public OutgoingPacket( IPPacket p, long sentAt ) {
			this.packet = p;
			this.sentAt = sentAt;
		}
	}
	
	
	public TCPSession( int state ) {
		this.state = state;
	}
	
	protected boolean flagPresent( int checkFor, int flags ) { return (flags & checkFor) == checkFor; } 
	
	public synchronized TCPSegment handleIncomingPacket( TCPSegment s ) {
		// How much to increment outgoingSequenceNumber by
		// in addition to the amount of data sent
		int stateChangesSent = 0;
		boolean ackRequired = false;
		int ackFlags = 0;
		
		switch( state ) {
		case( STATE_LISTEN ):
			if( flagPresent( TCPFlags.SYN, s.flags ) ) {
				ackFlags = TCPFlags.SYN;
				ackRequired = true;
				incomingSequenceNumber = s.sequenceNumber+1;
				state = STATE_SYN_RECEIVED;
				stateChangesSent += 1;
			}
			break;
		case( STATE_FIN_WAIT_1 ):
			if( flagPresent(TCPFlags.FIN|TCPFlags.ACK, s.flags) ) {
				state = STATE_TIME_WAIT;
			}
		}
		
		if( flagPresent( TCPFlags.FIN, s.flags ) ) {
			ackRequired = true;
			ackFlags |= TCPFlags.FIN;
			if( state < STATE_FIN_WAIT_1 ) {
				// If we haven't already acknowledged the FIN request...
				incomingSequenceNumber += 1;
				stateChangesSent += 1;
			}
		}
		
		if( s.sequenceNumber == incomingSequenceNumber && s.dataSize > 0 ) {
			incomingSequenceNumber += s.dataSize;
			ackRequired = true;
			System.err.print("got data: ");
			System.err.write( s.buffer, s.dataOffset, s.dataSize );
		}
		
		if( ackRequired ) {
			TCPSegment seg = TCPSegment.createResponse( s,
				outgoingSequenceNumber, incomingSequenceNumber,
				ackFlags | TCPFlags.ACK, 16384,
				ByteUtil.EMPTY_BTYE_ARRAY, 0, 0
			);
			
			outgoingSequenceNumber += stateChangesSent;
			
			return seg;
		} else {
			return null;
		}
	}
	
	public synchronized TCPSegment tick() {
		return null;
	}
}
