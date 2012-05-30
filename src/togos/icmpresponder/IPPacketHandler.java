package togos.icmpresponder;

import java.io.IOException;
import java.io.PrintStream;
import java.io.OutputStream;

import togos.blob.ByteChunk;
import togos.icmpresponder.packet.ICMP6Message;
import togos.icmpresponder.packet.IP6Packet;
import togos.icmpresponder.packet.IPPacket;
import togos.icmpresponder.packet.TCPSegment;
import togos.icmpresponder.tcp.TCPSession2;

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
			out.println("    Payload size: "+m.getPayloadSize());
			out.println("    Checksum: "+m.icmpChecksum );
			if( m.ipPacket instanceof IP6Packet ) {
				out.println("    Calculated checksum: "+ICMP6Message.calculateIcmp6Checksum( (IP6Packet)m.ipPacket ));
			}
		case( 6 ):
			TCPSegment tm = TCPSegment.parse( p );
			out.println( "  "+tm.toString() );
			if( tm.ipPacket instanceof IP6Packet ) {
				out.println("    Calculated checksum: "+ICMP6Message.calculateIcmp6Checksum( (IP6Packet)tm.ipPacket ));
				out.println("    Calculated checksum 2: "+TCPSegment.calculateChecksum( tm ));
			}
		}
	}
	
	protected static void dumpPacket( ByteChunk c, PrintStream out ) {
		IPPacket p = IPPacket.parse( c.getBuffer(), c.getOffset(), c.getSize() );
		if( p instanceof IP6Packet ) {
			out.println("IP6 Packet");
			out.println("  From: "+AddressUtil.formatIp6Address(p.getBuffer(), p.getSourceAddressOffset()));
			out.println("  To:   "+AddressUtil.formatIp6Address(p.getBuffer(), p.getDestinationAddressOffset()));			
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
	
	TCPSession2 tcpSession = new TCPSession2( new Sink<TCPSegment>() {
		public void give(TCPSegment s) {
			tryReply(s.ipPacket);
		};
	}, new OutputStream() {
		@Override public void write( byte[] buf, int off, int len ) {
			System.err.print( "Received data: " );
			System.err.write( buf, off, len );
			System.err.println();
		}
		@Override public void write(int b) throws IOException {
			write( new byte[]{ (byte)b }, 0, 1 );
		}
	});
	
	public void give( IPPacket p ) throws Exception {
		System.err.print("Received: ");
		dumpPacket( p, System.err );
		
		switch( p.getPayloadProtocolNumber() ) {
		case( 6 ):
			TCPSegment s = TCPSegment.parse( p );
			tcpSession.handleIncomingPacket( s );
		case( 58 ):
			ICMP6Message m = ICMP6Message.parse( p );
			if( m.icmpMessageType == 128 ) {
				ICMP6Message reply = ICMP6Message.create(
					p.buffer, p.getDestinationAddressOffset(),
					p.buffer, p.getSourceAddressOffset(), 
					64, 129, 0, m.getBuffer(), m.getPayloadOffset(), m.getPayloadSize()
				);
				tryReply( reply.ipPacket );
			}
			
			break;
		}
	}
}
