package togos.icmpresponder.tcp;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Random;

import togos.icmpresponder.ByteUtil;
import togos.icmpresponder.Sink;
import togos.icmpresponder.packet.TCPSegment;

public class TCPSession2
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
	protected final Sink<TCPSegment> outgoingSegmentSink;
	protected int acknowledgedOutgoingSequence;
	protected int currentOutgoingSequence;
	
	public TCPSession2( Sink<TCPSegment> outgoingSegmentSink, OutputStream incomingDataSink ) {
		this.outgoingSegmentSink = outgoingSegmentSink;
		this.incomingDataSink = incomingDataSink;
		this.currentOutgoingSequence = new Random().nextInt();
		this.acknowledgedOutgoingSequence = currentOutgoingSequence;
	}
	
	protected synchronized TCPSegment _handleIncomingPacket( TCPSegment s ) throws IOException {
		boolean sendSyn = false;
		boolean sendFin = false;
		
		if( s.isSyn() && !firstSynReceived ) {
			firstSynReceived = true;
			sendSyn = !s.isAck();
			receivedIncomingSequence = s.sequenceNumber;
		}
		
		// TODO: handle incoming ack numbers,
		// which are independent of incoming sequence numbers
		
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
			sendFin = true; // Not necessarily true if we have more data to send, first
		}
		
		boolean sendAck = (s.getSequenceDelta() != 0);
		receivedIncomingSequence = s.sequenceNumber + s.getSequenceDelta();
		
		if( sendAck || sendSyn || sendFin ) {
			int ackFlags = TCPFlags.ACK;
			if( sendSyn ) ackFlags |= TCPFlags.SYN;
			if( sendFin ) ackFlags |= TCPFlags.FIN;
			TCPSegment res = TCPSegment.createResponse( s,
				currentOutgoingSequence, receivedIncomingSequence,
				ackFlags, 16384,
				ByteUtil.EMPTY_BTYE_ARRAY, 0, 0
			);
			currentOutgoingSequence += res.getSequenceDelta();
			return res;
		} else {
			return null;
		}
	}
	
	public void handleIncomingPacket( TCPSegment s ) throws Exception {
		TCPSegment out = _handleIncomingPacket(s);
		if( out != null ) outgoingSegmentSink.give(out);
	}
}
