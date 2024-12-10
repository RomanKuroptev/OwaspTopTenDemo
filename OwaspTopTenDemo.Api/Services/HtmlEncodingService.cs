using System.Text.Encodings.Web;

namespace OwaspTopTenDemo.Api.Services
{
    public class HtmlEncodingService
    {
        private readonly HtmlEncoder _encoder;

        public HtmlEncodingService(HtmlEncoder encoder)
        {
            _encoder = encoder;
        }

        public string Encode(string input)
        {
            return _encoder.Encode(input);
        }
    }
}