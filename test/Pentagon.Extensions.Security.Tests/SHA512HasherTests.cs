using System;
using Xunit;

namespace Pentagon.Extensions.Security.Tests
{
    public class SHA512HasherTests
    {
        [Fact]
        public void HashPassword_ReturnsHashOfCorrectLength()
        {
            var password = "start";
            
            var service = new Sha512Hasher(16);

            var hash = service.HashPassword(password);
            
            Assert.Equal(128 + 16, hash.Length);
        }

        [Fact]
        public void VerifyHashedPassword_ReturnsTrueIfSaltedHashIsCorrect()
        {
            var password = "start";

            var hash = "CD3CA530CAEE1AABAC0EBBD2EA45C568BDD1442DA5724D22AD5C51461FCCB3F304806658486C0790053683CF875A5EBB62514404008AECCCE9BCC3F7BF5ADEE8";

            var salt = RandomHelper.GenerateRandom(16);

            var service = new Sha512Hasher(16);

           var result = service.VerifyHashedPassword(salt +hash, password);

           Assert.True(result);
        }

        [Fact]
        public void VerifyHashedPassword_ReturnsFalseIfSaltedHashIsNotCorrect()
        {
            var password = "start";

            var hash = "CD3CA53077771AABAC0EBBD2EA45C568BDD1442DA5724D22AD5C51461FCCB3F304806658486C0790053683CF875A5EBB62514404008AECCCE9BCC3F7BF5ADEE8";

            var salt = RandomHelper.GenerateRandom(16);

            var service = new Sha512Hasher(16);

            var result = service.VerifyHashedPassword(salt + hash, password);

            Assert.False(result);
        }
    }
}
