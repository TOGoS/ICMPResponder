package togos.icmpresponder;

import java.io.PrintStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;

import togos.blob.ByteChunk;
import togos.icmpresponder.packet.ICMP6Message;
import togos.icmpresponder.packet.IP6Packet;
import togos.icmpresponder.packet.IPPacket;
import togos.icmpresponder.packet.TCPSegment;
import togos.icmpresponder.tcp.TCPSegmentHandler;
import togos.icmpresponder.tcp.junk.ThreadyTCPServer;

public class IPPacketHandler implements Sink<IPPacket>
{
	public final Sink<IPPacket> responseSink;
	
	public IPPacketHandler( Sink<IPPacket> responseSink ) {
		this.responseSink = responseSink;
	}
	
	protected static void dumpPayload( IPPacket p, PrintStream out ) {
		switch( p.getPayloadProtocolNumber() ) {
		case( 58 ):
			ICMP6Message m = ICMP6Message.parse( p );
			out.println("  ICMP6 message");
			out.println("    Type: "+m.icmpMessageType );
			out.println("    Code: "+m.icmpMessageCode );
			out.println("    Payload size: "+m.getPayload().getSize());
			out.println("    Checksum: "+m.icmpChecksum );
			if( m.ipPacket instanceof IP6Packet ) {
				out.println("    Calculated checksum: "+ICMP6Message.calculateIcmp6Checksum( (IP6Packet)m.ipPacket ));
			}
			break;
		case( 6 ):
			TCPSegment tm = TCPSegment.parse( p );
			out.println( "  "+tm.toString() );
			if( tm.ipPacket instanceof IP6Packet ) {
				out.println("    Calculated checksum: "+ICMP6Message.calculateIcmp6Checksum( (IP6Packet)tm.ipPacket ));
				out.println("    Calculated checksum 2: "+TCPSegment.calculateChecksum( tm ));
			}
			break;
		}
	}
	
	protected static void dumpPacket( ByteChunk c, PrintStream out ) {
		IPPacket p = IPPacket.parse( c.getBuffer(), c.getOffset(), c.getSize() );
		if( p instanceof IP6Packet ) {
			out.println("IP6 Packet");
			out.println("  From: "+AddressUtil.formatIp6Address(p.getSourceAddress()));
			out.println("  To:   "+AddressUtil.formatIp6Address(p.getDestinationAddress()));			
		} else {
			out.println("Some non-IP6 packet");
		}
		dumpPayload( p, out );
	}
	
	protected void tryReply( IPPacket p ) {
		try {
			System.err.print("Sending ");
			dumpPacket(p, System.err);
			responseSink.give( p );
		} catch( Exception e ) {
			System.err.println("Failed to send reply packet: "+e.getMessage());
		}
	}
	
	Sink<IPPacket> outgoingPacketSink = new Sink<IPPacket>() {
		public void give(IPPacket s) {
			tryReply(s);
		};
	};
	Sink<TCPSegment> outgoingTcpSegmentSink = new Sink<TCPSegment>() {
		public void give(TCPSegment s) {
			tryReply(s.ipPacket);
		};
	};
	
	TCPSegmentHandler tcpHandler = new TCPSegmentHandler( outgoingTcpSegmentSink );
	ThreadyTCPServer tTcpServer = new ThreadyTCPServer( outgoingPacketSink );
	
	public void give( IPPacket p ) throws Exception {
		System.err.print("Received: ");
		dumpPacket( p, System.err );
		
		switch( p.getPayloadProtocolNumber() ) {
		case( 6 ):
			TCPSegment s = TCPSegment.parse( p );
			if( !s.wellFormed ) return;
			tcpHandler.give( s );
			// tTcpServer.handleTcpSegment(s);
			break;
		case( 58 ):
			ICMP6Message m = ICMP6Message.parse( p );
			if( m.icmpMessageType == 128 ) {
				ICMP6Message reply = ICMP6Message.create(
					p.getDestinationAddress(),
					p.getSourceAddress(), 
					64, 129, 0, m.getPayload()
				);
				tryReply( reply.ipPacket );
			}
			
			break;
		}
	}
	
	static SocketAddress lastReceivedFrom = null;
	public static void main( String[] args ) throws Exception {
		final DatagramSocket datagramSocket = new DatagramSocket(7777);
		final IPPacketHandler handler = new IPPacketHandler( new Sink<IPPacket>() {
			public void give(IPPacket p) throws Exception {
				datagramSocket.send( new DatagramPacket(p.getBuffer(), p.getOffset(), p.getSize(), lastReceivedFrom) );
			}
		});
		byte[] recvBuffer = new byte[2048];
		while( true ) {
			DatagramPacket p = new DatagramPacket( recvBuffer, 2048 );
			datagramSocket.receive(p);
			lastReceivedFrom = p.getSocketAddress();
			byte[] packetBuffer = new byte[p.getLength()];
			for( int i=packetBuffer.length-1; i>=0; --i ) {
				packetBuffer[i] = recvBuffer[i];
			}
			handler.give( IPPacket.parse( packetBuffer, 0, packetBuffer.length ) );
		}
	}
}
