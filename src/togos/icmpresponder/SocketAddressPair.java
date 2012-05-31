package togos.icmpresponder;

public interface SocketAddressPair
{
	public int getIpVersion();
	public byte[] getSourceAddressBuffer();
	public int getSourceAddressOffset();
	public int getSourcePort();
	public byte[] getDestinationAddressBuffer();
	public int getDestinationAddressOffset();
	public int getDestinationPort();
}
