using AkvTest.ClassLibrary;
using System;

namespace AkvTest.ConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            var obj = new Class1();
            Console.WriteLine($"{nameof(obj)}.{nameof(obj.Property1)} = '{obj.Property1}'");
            Console.ReadKey(true);
        }
    }
}
