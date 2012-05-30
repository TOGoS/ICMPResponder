package togos.icmpresponder;

import java.io.PrintStream;
import java.util.Random;

import togos.blob.ByteChunk;
import togos.icmpresponder.ICMPResponder.AddressUtil;
import togos.icmpresponder.packet.ICMP6Message;
import togos.icmpresponder.packet.IP6Packet;
import togos.icmpresponder.packet.IPPacket;
import togos.icmpresponder.packet.TCPSegment;

public class IPPacketHandler implements Sink<IPPacket>
{
	public final Sink<IPPacket> responseSink;
	
	public IPPacketHandler( Sink<IPPacket> responseSink ) {
		this.responseSink = responseSink;
	}
	
	protected void tryReply( IPPacket p ) {
		try {
			responseSink.give( p );
		} catch( Exception e ) {
			System.err.println("Failed to send reply packet: "+e.getMessage());
		}
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
	
	public void give( IPPacket p ) {
		System.err.print("Received: ");
		dumpPacket( p, System.err );
		
		switch( p.getPayloadProtocolNumber() ) {
		case( 6 ):
			TCPSegment tm = TCPSegment.parse( p );
			
			if( (tm.flags & TCPFlags.RST) != 0 ) {
				System.err.println("Connection reset!");
				System.exit(1);
			}
			
			if( tm.ipPacket instanceof IP6Packet ) {
				IP6Packet ip6 = (IP6Packet)tm.ipPacket;
				
				switch( tm.flags ) {
				case( TCPFlags.SYN ):
					TCPSegment synAck = TCPSegment.createV6(
						ip6.buffer, ip6.getDestinationAddressOffset(), tm.destPort,
						ip6.buffer, ip6.getSourceAddressOffset(), tm.sourcePort,
						new Random().nextInt(), tm.sequenceNumber+1,
						TCPFlags.SYN|TCPFlags.ACK, 16384,
						ByteUtil.EMPTY_BTYE_ARRAY, 0, 0 );
					tryReply( synAck.ipPacket );
				}
			}
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
