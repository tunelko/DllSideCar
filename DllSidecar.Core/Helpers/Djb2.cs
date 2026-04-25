namespace DllSidecar.Core.Helpers;

public static class Djb2
{
    public static uint Hash(string name)
    {
        uint h = 5381;
        foreach (char c in name)
            h = ((h << 5) + h + c) & 0xFFFFFFFF;
        return h;
    }

    public static uint HashInsensitive(string name)
    {
        uint h = 5381;
        foreach (char c in name.ToLowerInvariant())
            h = ((h << 5) + h + c) & 0xFFFFFFFF;
        return h;
    }
}
