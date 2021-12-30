using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Text;

namespace SampleProjectxUnitTest
{
    public class Startup
    {
        public void ConfigureHost(IHostBuilder hostBuilder)
        {
            //hostBuilder
            //    .ConfigureAppConfiguration(builder =>
            //    {
            //        builder
            //            .AddInMemoryCollection(new Dictionary<string, string>()
            //            {
            //                {"UserName", "Alice"}
            //            })
            //            .AddJsonFile("appsettings.json")
            //            ;
            //    })
            //    ;
        }

        public void ConfigureServices(IServiceCollection services, HostBuilderContext hostBuilderContext)
        {
            
        }

        public void Configure(IServiceProvider applicationServices)
        {
        }
    }
}
