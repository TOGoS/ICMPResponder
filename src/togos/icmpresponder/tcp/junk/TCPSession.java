package togos.icmpresponder.tcp.junk;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Random;

import togos.icmpresponder.ByteUtil;
import togos.icmpresponder.Sink;
import togos.icmpresponder.SocketAddressPair;
import togos.icmpresponder.packet.TCPSegment;
import togos.icmpresponder.tcp.TCPFlags;

/**
 * This class can be used in either a multi-threaded (one thread pushing incoming packets
 * and another reading them and pushing response data)
 * @author stevens
 *
 */
public class TCPSession
{
	static class OutgoingData {
		public OutgoingData next;
		
		public final int sequenceNumber;  
		public final byte[] buffer;
		public final int offset;
		public final int size;
		public final boolean syn;
		public final boolean fin;
		
		public int getSequenceDelta() {
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
	
	protected boolean firstSynReceived = false;
	protected int receivedIncomingSequence;
	protected final OutputStream incomingDataSink;
	
	protected OutgoingData sentDataList;
	protected OutgoingData sentDataListEnd;
	protected final Sink<TCPSegment> outgoingSegmentSink;
	protected int acknowledgedOutgoingSequence;
	protected int currentOutgoingSequence;
	protected int maxWindowSize = 32768;
	
	public SocketAddressPair outgoingSocketAddressPair;
	
	public TCPSession( Sink<TCPSegment> outgoingSegmentSink, OutputStream incomingDataSink ) {
		this.incomingDataSink = incomingDataSink;
		this.outgoingSegmentSink = outgoingSegmentSink;
		this.currentOutgoingSequence = new Random().nextInt();
		this.acknowledgedOutgoingSequence = currentOutgoingSequence;
	}
	
	protected synchronized TCPSegment dataSegment( OutgoingData dat ) {
		int flags = 0;
		if( dat.fin ) flags |= TCPFlags.FIN;
		return TCPSegment.create(
			outgoingSocketAddressPair,
			dat.sequenceNumber, receivedIncomingSequence,
			flags | TCPFlags.ACK, maxWindowSize,
			dat.buffer, dat.offset, dat.size
		);
	}
	
	protected synchronized TCPSegment _handleIncomingSegment( TCPSegment s ) throws IOException {
		boolean sendSyn = false;
		
		this.outgoingSocketAddressPair = s.getInverseAddressPair();
		
		if( s.isSyn() && !firstSynReceived ) {
			firstSynReceived = true;
			// syn => we are the server (and need to syn+ack back), syn+ack => we are the client 
			sendSyn = !s.isAck();
			receivedIncomingSequence = s.sequenceNumber;
		}
		
		if( s.ackNumber > acknowledgedOutgoingSequence ) {
			acknowledgedOutgoingSequence = s.ackNumber;
		}
		
		if( s.sequenceNumber != receivedIncomingSequence ) {
			// Then we missed some data and will ignore everything until we get
			// the one we are expecting!
			return null;
		}
		
		if( s.hasData() ) {
			incomingDataSink.write( s.buffer, s.dataOffset, s.dataSize );
		}
		if( s.isFin() ) {
			incomingDataSink.close();
		}
		
		boolean sendAck = (s.getSequenceDelta() != 0);
		receivedIncomingSequence = s.sequenceNumber + s.getSequenceDelta();
		
		notifyAll();
		
		if( sendAck || sendSyn ) {
			int ackFlags = TCPFlags.ACK;
			if( sendSyn ) ackFlags |= TCPFlags.SYN;
			
			TCPSegment res = TCPSegment.create(
				outgoingSocketAddressPair,
				currentOutgoingSequence, receivedIncomingSequence,
				// TODO: What should maxWindowSize be?
				// Can it be different for input/output?
				ackFlags, maxWindowSize,
				ByteUtil.EMPTY_BTYE_ARRAY, 0, 0
			);
			currentOutgoingSequence += res.getSequenceDelta();
			return res;
		} else {
			return null;
		}
	}
	
	public void handleIncomingSegment( TCPSegment s ) throws Exception {
		TCPSegment out = _handleIncomingSegment(s);
		if( out != null ) outgoingSegmentSink.give(out);
	}
	
	public int unacknowlegedBytes() {
		return currentOutgoingSequence - acknowledgedOutgoingSequence;
	}
	
	protected synchronized void add( OutgoingData dat ) {
		if( sentDataList == null ) {
			sentDataList = sentDataListEnd = dat;
		} else {
			sentDataListEnd.next = dat;
			sentDataListEnd = dat;
		}
		currentOutgoingSequence += dat.getSequenceDelta();
	}
	
	protected synchronized void send( OutgoingData dat ) throws Exception {
		add( dat );
		outgoingSegmentSink.give(dataSegment(dat));
	}
	
	public boolean send( byte[] buffer, int offset, int size ) throws Exception {
		if( size + unacknowlegedBytes() < maxWindowSize ) {
			OutgoingData dat = new OutgoingData(currentOutgoingSequence, buffer, offset, size, false, false);
			send( dat );
			return true;
		} else {
			return false;
		}
	}
	
	public synchronized void sendBlocking( byte[] buffer, int offset, int size ) throws Exception {
		while( size > 0 ) {
			int sendAmt = size > 1024 ? 1024 : size;
			while( !send(buffer,offset,sendAmt) ) wait();
			offset += sendAmt;
			size -= sendAmt;
		}
	}
	
	public void sendFin() throws Exception {
		send( new OutgoingData(currentOutgoingSequence, ByteUtil.EMPTY_BTYE_ARRAY, 0, 0, false, true));
	}
}
