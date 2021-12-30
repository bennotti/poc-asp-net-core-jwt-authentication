using System;
using System.Collections.Generic;
using System.Text;

namespace SampleProject.Core.Settings
{
    public class JwtSettings
    {
        public string Secret { get; set; }
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public int Seconds { get; set; }
    }
}
