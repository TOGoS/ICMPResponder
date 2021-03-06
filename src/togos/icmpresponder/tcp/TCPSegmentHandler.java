package togos.icmpresponder.tcp;

import java.util.Random;

import togos.blob.SimpleByteChunk;
import togos.icmpresponder.Sink;
import togos.icmpresponder.SocketAddressPair;
import togos.icmpresponder.packet.TCPSegment;

/**
 * Single-threaded class for tracking TCP connections
 */
public class TCPSegmentHandler implements Sink<TCPSegment>
{
	static final int WINDOW_SIZE = 32768;
	
	/** Sends outgoing data */
	static interface TCPDataWriter {
		public void write( byte[] data, int off, int len, boolean close );
	}
	
	/** Handles incoming data */
	static interface TCPDataHandler {
		void handleData( byte[] data, int off, int len, boolean fin, TCPDataWriter out );
	}
	
	static class TCPOutputBuffer implements TCPDataWriter {
		/** Data that has yet to be acknowledged by the other end */
		protected byte[] buffer = SimpleByteChunk.EMPTY_BYTE_ARRAY;
		protected boolean synAcked;
		protected boolean closed, closeAcked;
		/**
		 * Ssequence number of the first unacknowledged byte in the stream.
		 * (SYN and FIN both count as one byte).
		 * When the closing of this stream (FIN) has been acked,
		 * closeAcked will be true, the buffer will be empty
		 * and this should be one 'past the end of the empty buffer'.
		 * 
		 * If there is data in buffer, the fist byte has this sequence number.
		 **/
		protected int sequence = 0;
		
		public TCPOutputBuffer( int sendSequence ) {
			this.sequence = sendSequence + 1;  // 1 = the syn that we must send in the first packet
		}
		
		static byte[] append( byte[] a, byte[] b, int boff, int blen ) {
			assert( boff >= 0 );
			assert( boff <= b.length );
			assert( boff + blen <= b.length );
			
			byte[] c = new byte[a.length + blen];
			for( int i=0; i<a.length; ++i ) c[i] = a[i];
			for( int i=0; i<blen; ++i ) c[a.length+i] = b[boff+i];
			return c;
		}
		
		static byte[] slice( byte[] buf, int off ) {
			assert( off >= 0 );
			assert( off < buf.length );
			
			if( off == 0 ) return buf;
			if( off == buf.length ) return SimpleByteChunk.EMPTY_BYTE_ARRAY;
			
			byte[] newBuf = new byte[buf.length-off];
			for( int i=0; i<newBuf.length; ++i ) {
				newBuf[i] = buf[off+i];
			}
			return newBuf;
		}
		
		/**
		 * Append data to the to-be-written buffer.
		 * If close is true, no more data will ever be added.
		 */
		public void write(byte[] data, int off, int len, boolean close) {
			assert( !closed );
			assert( len >= 0 );
			
			if( close ) closed = true;
			if( len > 0 ) buffer = append( buffer, data, off, len );
		}
		
		/**
		 * Clear data that's been acknowledged received by the other end.
		 */
		protected void ack( int seq ) {
			synAcked = true;
			if( seq < sequence ) return;
			
			if( closed && seq == sequence + buffer.length + 1 ) {
				buffer = SimpleByteChunk.EMPTY_BYTE_ARRAY;
				sequence = seq;
				closeAcked = true;
				return;
			}
			
			if( seq > sequence + buffer.length ) {
				System.err.println("Received unexpected ack of more data than has been buffered: "+seq+"/"+sequence);
				return;
			}
			
			int trim = seq - sequence;
			buffer = slice(buffer, trim);
			sequence = seq;
		}
	}
	
	static class TCPSession {
		// server is the 'source' address:
		public final SocketAddressPair rap;
		public final TCPDataHandler handler;
		public final TCPOutputBuffer outBuf;
		public int inputSequence;
		/**
		 * True if we think the other end can accept
		 * data and SYN/FIN flags in the same segment.
		 */
		public boolean combine;
		
		public TCPSession( SocketAddressPair outgoingAddressPair, TCPDataHandler handler, int inSeq, int outSeq, boolean combine ) {
			assert( outgoingAddressPair != null );
			assert( handler != null );
			
			this.rap = outgoingAddressPair;
			this.handler = handler;
			this.outBuf = new TCPOutputBuffer( outSeq );
			this.inputSequence = inSeq;
			this.combine = combine;
		}
	}
	
	final Sink<TCPSegment> outputSegmentSink;
	final Random rand = new Random();
	
	public TCPSegmentHandler( Sink<TCPSegment> outputSegmentSink ) {
		this.outputSegmentSink = outputSegmentSink;
	}
	
	TCPSession sess;
	
	protected boolean sendData( SocketAddressPair sap, TCPOutputBuffer buf, boolean includeSyn, boolean includeData, boolean includeFinIfReached, int ackSeq )
		throws Exception
	{
		// This function doesn't currently handle the send-fin-but-no-data case, so:
		assert( !includeFinIfReached || includeData );
		
		int payloadSize = includeData ? Math.min( buf.buffer.length, 1024 ) : 0;
		boolean includeFin = includeFinIfReached && payloadSize == buf.buffer.length && buf.closed && !buf.closeAcked;
		
		if( !includeSyn && payloadSize == 0 && !includeFin ) {
			// then send nothing!
			return false;
		}
		
		outputSegmentSink.give( TCPSegment.create(
			sap,
			includeSyn ? buf.sequence - 1 : buf.sequence,
			ackSeq,
			(includeSyn ? TCPFlags.SYN : 0) | (includeFin ? TCPFlags.FIN : 0 ) | TCPFlags.ACK,
			WINDOW_SIZE,
			buf.buffer, 0, payloadSize
		));
		return true;
	}
	
	protected boolean sendSomeOutgoingData( TCPSession sess ) throws Exception {
		SocketAddressPair rap = sess.rap;
		boolean anythingSent = false;
		if( sess.combine ) {
			anythingSent = sendData( rap, sess.outBuf, !sess.outBuf.synAcked, true, true, sess.inputSequence ); 
		} else {
			if( !sess.outBuf.synAcked ) {
				anythingSent |= sendData( rap, sess.outBuf, true, false, false, sess.inputSequence );
			}
			if( sess.outBuf.buffer.length > 0 ) {
				anythingSent |= sendData( rap, sess.outBuf, false, true, false, sess.inputSequence );
			}
			if( sess.outBuf.buffer.length <= 1024 && sess.outBuf.closed && !sess.outBuf.closeAcked ) {
				outputSegmentSink.give( TCPSegment.create(
					rap,
					sess.outBuf.sequence + sess.outBuf.buffer.length,
					sess.inputSequence,
					TCPFlags.FIN | TCPFlags.ACK,
					WINDOW_SIZE,
					SimpleByteChunk.EMPTY_BYTE_ARRAY, 0, 0
				));
				anythingSent = true;
			}
		}
		return anythingSent;
	}
	
	public void give( TCPSegment inSeg ) throws Exception {
		int outSeq;
		if( inSeg.isSyn() ) {
			// Start a new session!
			outSeq = rand.nextInt();
			
			TCPDataHandler handler = new TCPDataHandler() {
				public void handleData(
					byte[] data, int off, int len, boolean fin,
					TCPDataWriter out
				) {
					System.err.println( "Got "+len+" bytes"+(fin ? " and a fin" : "")+".");
					// Echo it right back!
					out.write(data, off, len, fin);
				}
			};
			
			sess = new TCPSession( inSeg.getInverseAddressPair(), handler, inSeg.sequenceNumber+1, outSeq, inSeg.dataSize > 0 );
		} else if( sess == null ) {
			// Invalid!
			return;
		} else if( inSeg.sequenceNumber < sess.inputSequence ) {
			// Old data; ignore!
			// Actually it could still be valid and we'd need to accept
			// this if inSeg.sequenceNumber + inSeg.getSequenceDelta() < sess.inputSequence
			return;
		} else if( inSeg.sequenceNumber > sess.inputSequence ) {
			// Too new; ignore?
			return;
		} else {
			outSeq = sess.outBuf.sequence;
		}
		
		sess.handler.handleData( inSeg.getBuffer(), inSeg.dataOffset, inSeg.dataSize, inSeg.isFin(), sess.outBuf );
		sess.inputSequence = inSeg.sequenceNumber + inSeg.getSequenceDelta();
		
		if( inSeg.isAck() ) sess.outBuf.ack( inSeg.ackNumber );
		
		boolean ackRequired = inSeg.isSyn() || inSeg.isFin() || inSeg.hasData();
		// 'response address pair'
		SocketAddressPair rap = inSeg.getInverseAddressPair();
		
		boolean ackSent = sendSomeOutgoingData(sess);
		
		if( ackRequired && !ackSent ) {
			outputSegmentSink.give( TCPSegment.create(
				rap,
				sess.outBuf.sequence + sess.outBuf.buffer.length,
				sess.inputSequence,
				TCPFlags.ACK,
				WINDOW_SIZE,
				SimpleByteChunk.EMPTY_BYTE_ARRAY, 0, 0
			));
		}
		
		// TODO: as long as there is data in the output buffers or unacked fins,
		// register the session as needs checking up on.
		
		// TODO: Remove closed sessions when both ends are closed and fins have been acknowledged
	}
}
