package togos.icmpresponder;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;

import togos.icmpresponder.packet.IPPacket;

public class NewResponder
{
	DatagramSocket dgs;
	public NewResponder( DatagramSocket dgs ) {
		this.dgs = dgs;
	}
	
	SocketAddress lastReceivedFrom = null;
	IPPacketHandler handler = new IPPacketHandler( new Sink<IPPacket>() {
		public void give(IPPacket p) throws Exception {
			dgs.send( new DatagramPacket(p.getBuffer(), p.getOffset(), p.getSize(), lastReceivedFrom) );
		}
	});
	
	public void run() throws IOException {
		byte[] recvBuffer = new byte[2048];
		while( true ) {
			DatagramPacket p = new DatagramPacket( recvBuffer, 2048 );
			dgs.receive(p);
			lastReceivedFrom = p.getSocketAddress();
			byte[] packetBuffer = new byte[p.getLength()];
			for( int i=packetBuffer.length-1; i>=0; --i ) {
				packetBuffer[i] = recvBuffer[i];
			}
			handler.give( IPPacket.parse( packetBuffer, 0, packetBuffer.length ) );
		}
	}
	
	public static void main( String[] args ) throws Exception {
		DatagramSocket s = new DatagramSocket(7777);
		new NewResponder(s).run();
	}
}
