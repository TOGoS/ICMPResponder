package togos.icmpresponder.tcp;

import togos.icmpresponder.ByteUtil;

public class TCPWindow
{
	static class OutgoingData {
		public OutgoingData next;
		
		public final int sequenceNumber;  
		public final byte[] buffer;
		public final int offset;
		public final int size;
		public final boolean syn;
		public final boolean fin;
		
		public int getTotalSequenceDeltat() {
			return size + (syn ? 1 : 0) + (fin ? 1 : 0);
		}
		
		public OutgoingData( int seqNum, byte[] buf, int off, int siz, boolean syn, boolean fin ) {
			this.sequenceNumber = seqNum;
			this.buffer = buf;
			this.offset = off;
			this.size   = siz;
			this.syn    = syn;
			this.fin    = fin;
		}
	}
	
	OutgoingData sentListBegin;
	OutgoingData sentListEnd;
	int sentBufferSize;
	int nextSequenceNumber;
	
	public TCPWindow( int initialSequenceNumber ) {
		add( new OutgoingData( initialSequenceNumber, ByteUtil.EMPTY_BTYE_ARRAY, 0, 0, true, false ) );
	}
	
	public synchronized void fastForward( int outgoingSequenceNumber ) {
		while( sentListBegin != null && sentListBegin.sequenceNumber < outgoingSequenceNumber ) {
			sentBufferSize -= sentListBegin.size;
			sentListBegin = sentListBegin.next;
		}
		if( sentListBegin == null ) {
			sentListEnd = null;
		}
		notifyAll();
	}
	
	public synchronized void add( OutgoingData newEntry ) {
		if( sentListEnd == null ) {
			sentListBegin = sentListEnd = newEntry;
		} else {
			sentListEnd.next = newEntry;
		}
		nextSequenceNumber += newEntry.getTotalSequenceDeltat();
		sentBufferSize += newEntry.size;
		notifyAll();
	}
	
	public synchronized void add( byte[] data, int offset, int size, boolean fin ) {
		add( new OutgoingData( nextSequenceNumber, data, offset, size, false, true ) );
	}
}
