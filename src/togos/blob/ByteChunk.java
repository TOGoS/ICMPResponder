package togos.blob;

public interface ByteChunk
{
	public int getOffset();
	public int getSize();
	public byte[] getBuffer();
}
