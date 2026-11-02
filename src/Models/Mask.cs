using System.Text.RegularExpressions;

namespace OrderApi.Models;

public static class Mask
{
    // Static masking: keep first 6 and last 4 of a PAN, replace the middle with '*'
    public static string? MaskPan(string? pan)
    {
        if (string.IsNullOrWhiteSpace(pan)) return null;
        var digits = Regex.Replace(pan, @"[^\d]", "");
        if (digits.Length < 12) return new string('*', digits.Length);
        return digits.Substring(0, 6) + "******" + digits.Substring(digits.Length - 4);
    }
}
