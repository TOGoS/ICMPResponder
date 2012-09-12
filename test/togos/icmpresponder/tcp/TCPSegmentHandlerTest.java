package togos.icmpresponder.tcp;

import java.util.ArrayList;

import junit.framework.TestCase;
import togos.blob.ByteChunk;
import togos.blob.SimpleByteChunk;
import togos.blob.util.BlobUtil;
import togos.icmpresponder.SimpleSocketAddressPair;
import togos.icmpresponder.Sink;
import togos.icmpresponder.SocketAddressPair;
import togos.icmpresponder.packet.TCPSegment;

public class TCPSegmentHandlerTest extends TestCase
{
	TCPSegmentHandler tsh;
	ArrayList<TCPSegment> responseSegments;
	
	public void setUp() {
		tsh = new TCPSegmentHandler( new Sink<TCPSegment>() {
			@Override
			public void give(TCPSegment inSeg) throws Exception {
				responseSegments.add(inSeg);
			}
		});
		responseSegments = new ArrayList();
	}
	
	protected static ByteChunk segPayload( TCPSegment s ) {
		return new SimpleByteChunk(s.buffer, s.dataOffset, s.dataSize);
	}
	
	static final SocketAddressPair sap = new SimpleSocketAddressPair( 6,
		new byte[]{20,20,0,0,0,0,0,0,0,0,0,0,0,0,0,1}, 12345, 
		new byte[]{20,20,0,0,0,0,0,0,0,0,0,0,0,0,0,2}, 5 );

	static final ByteChunk helloChunk = BlobUtil.byteChunk("Hello.");	
	
	// TODO: test with initial sequence numbers near Integer.MAX_VALUE
	
	public void testCombinedTransaction() throws Exception {
		int initSeq = 1000;
		int zSequence;
		
		tsh.give( TCPSegment.create( sap, initSeq, 0, TCPFlags.SYN|TCPFlags.FIN, 10000, helloChunk.getBuffer(), helloChunk.getOffset(), helloChunk.getSize() ) );
		
		{
			assertEquals( 1, responseSegments.size() );
			TCPSegment zs = responseSegments.get(0);
			assertEquals( TCPFlags.SYN|TCPFlags.FIN|TCPFlags.ACK, zs.flags );
			assertEquals( helloChunk, segPayload(zs) );
			assertEquals( initSeq + 8, zs.ackNumber );
			zSequence = zs.sequenceNumber + zs.getSequenceDelta();
		}
		
		tsh.give( TCPSegment.create( sap, initSeq+8, zSequence, TCPFlags.ACK, 10000, SimpleByteChunk.EMPTY_BYTE_ARRAY, 0, 0 ) );
		
		assertEquals( 1, responseSegments.size() );
	}
	
	public void testUnCombinedTransaction() throws Exception {
		int initSeq = 1000;
		int zSequence;
		
		tsh.give( TCPSegment.create( sap, initSeq, 0, TCPFlags.SYN, 10000, SimpleByteChunk.EMPTY_BYTE_ARRAY, 0, 0 ) );
		
		{
			assertEquals( 1, responseSegments.size() );
			TCPSegment zs = responseSegments.get(0);
			assertEquals( TCPFlags.SYN|TCPFlags.ACK, zs.flags );
			assertEquals( SimpleByteChunk.EMPTY, segPayload(zs) );
			assertEquals( initSeq + 1, zs.ackNumber );
			zSequence = zs.sequenceNumber + zs.getSequenceDelta();
		}
		
		tsh.give( TCPSegment.create( sap, initSeq+1, zSequence, TCPFlags.ACK, 10000, helloChunk.getBuffer(), helloChunk.getOffset(), helloChunk.getSize() ) );
		
		{
			assertEquals( 2, responseSegments.size() );
			TCPSegment zs = responseSegments.get(1);
			assertEquals( TCPFlags.ACK, zs.flags );
			assertEquals( helloChunk, segPayload(zs) );
			assertEquals( initSeq + 7, zs.ackNumber );
			assertEquals( zSequence, zs.sequenceNumber );
			zSequence = zs.sequenceNumber + zs.getSequenceDelta();
		}
		
		tsh.give( TCPSegment.create( sap, initSeq+7, zSequence, TCPFlags.ACK|TCPFlags.FIN, 10000, SimpleByteChunk.EMPTY_BYTE_ARRAY, 0, 0 ) );

		{
			assertEquals( 3, responseSegments.size() );
			TCPSegment zs = responseSegments.get(2);
			assertEquals( TCPFlags.ACK|TCPFlags.FIN, zs.flags );
			assertEquals( SimpleByteChunk.EMPTY, segPayload(zs) );
			assertEquals( initSeq + 8, zs.ackNumber );
			assertEquals( zSequence, zs.sequenceNumber );
			zSequence = zs.sequenceNumber + zs.getSequenceDelta();
		}
		
		tsh.give( TCPSegment.create( sap, initSeq+8, zSequence, TCPFlags.ACK, 10000, SimpleByteChunk.EMPTY_BYTE_ARRAY, 0, 0 ) );
		
		assertEquals( 3, responseSegments.size() );
	}
}
