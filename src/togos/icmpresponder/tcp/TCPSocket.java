package togos.icmpresponder.tcp;

import togos.icmpresponder.packet.TCPSegment;

public class TCPSocket
{
	public boolean write( byte[] buf, int offset, int size ) {
		return false;
	}
	
	public boolean closeWrite() {
		return false;
	}
	
	/** Returns the next TCPSegment containing data, or null if there is no more (i.e. we found a FIN packet) */
	public TCPSegment read() {
		return null;
	}
}
