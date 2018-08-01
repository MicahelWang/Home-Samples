using System;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.Models;

namespace Samples.NetworkInterceptor
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            Core core = new Core();
            core.Run();
        }
    }
}
