using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SampleProject.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class JwtAuthenticationController : ControllerBase
    {
        
        private readonly ILogger<JwtAuthenticationController> _logger;
        private readonly Random _random;

        public JwtAuthenticationController(Random random, ILogger<JwtAuthenticationController> logger)
        {
            _logger = logger;
            _random = random;
        }

        [HttpGet]
        public IEnumerable<WeatherForecast> Get()
        {
            _logger.LogInformation("Obtendo WeatherForecast");
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = _random.Next(-20, 55),
                Summary = Summaries[_random.Next(Summaries.Length)]
            })
            .ToArray();
        }
    }
}
