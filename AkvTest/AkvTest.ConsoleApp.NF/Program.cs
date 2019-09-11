using AkvTest.ClassLibrary.NF;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AkvTest.ConsoleApp.NF
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            var obj = new Class2();
            Console.WriteLine($"{nameof(obj)}.{nameof(obj.Property1)} = '{obj.Property1}'");
            Console.ReadKey(true);
        }
    }
}
