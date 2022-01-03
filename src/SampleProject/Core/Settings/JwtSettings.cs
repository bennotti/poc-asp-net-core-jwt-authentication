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
        private int _expireInSeconds;
        public int? ExpireInSeconds {
            get { return _expireInSeconds; } 
            set {
                if (value.HasValue && value.Value > 0) {
                    _expireInSeconds = value.Value;
                } else {
                    _expireInSeconds = 900;
                }
            }
        }
    }
}
