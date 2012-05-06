package togos.icmpresponder;

import togos.icmpresponder.packet.IPPacket;

public class InvalidIPPacket extends IPPacket
{
	protected String note;
	
	public InvalidIPPacket( byte[] buffer, int offset, int size, String note ) {
		super( buffer, offset, size );
		this.note = note;
	}
	
	public InvalidIPPacket( byte[] buffer, int offset, int size ) {
		this( buffer, offset, size, "Invalid IP packet" );
	}
	
	@Override public int getSourceAddressOffset() { return 0; }
	@Override public int getSourceAddressSize() { return 0; }
	@Override public int getDestinationAddressOffset() { return 0; }
	@Override public int getDestinationAddressSize() { return 0; }
	@Override public int getPayloadProtocolNumber() { return 0; }
	@Override public int getHopLimit() { return 0; }
	@Override public int getPayloadOffset() { return 0; }
	@Override public int getPayloadSize() { return 0; }
}
