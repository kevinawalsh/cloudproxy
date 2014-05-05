//
//  File: divpolys.cc
//  Description: calculate the division polynomials mod p
//
//  Copyright (c) 2014, John Manferdelli.  All rights reserved.
//
// Use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the Apache License dated
// January, 2004, (the "License").  This License is contained in the
// top level directory originally provided with the CloudProxy Project.
// Your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// If you distribute this file (or portions derived therefrom), you must
// include License in or with the file and, in the event you do not include
// the entire License in the file, the file must contain a reference
// to the location of the License.


#include "common.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "polyarith.h"
#include "stdio.h"

//
// phi[0]= 0
// phi[1]= 1
// phi[2]= 2y
// phi[3]=  3x^4+6ax+12bx-a^2
// phi[4]= 4y(x^6+5ax^4+20bx^3-5a^2x^2-4abx-8b^2-a^3
// phi[2m+1]= phi[m+2]phi^3[m]-phi[m-1]phi^3[m+1]
// phi[2m]= phi[m]/phi[2](phi[m+2]phi^2[m-1]-phi[m-2]phi^2[m+1])
// theta[m]= x phi^2[m]-phi[m+1]phi[m-1]
// omega[m]= (phi[m]/(2 phi[2]) (phi[m+2] phi[m-1]-phi[m-2] phi^2[m+1])


int             g_maxcoeff= -1;   // max coeff calculated
rationalpoly**  g_phi= NULL;      // x rational function
i16*            g_exp_y= NULL;    // exponent of y


// ----------------------------------------------------------------------------


bool evenphirecurrence(int m, polynomial& curve_x_poly);
bool oddphirecurrence(int m, polynomial& curve_x_poly);
typedef rationalpoly* rational_p_t;


bool initphicalc(int max, polynomial& curve_x_poly) {
  if(max<5)
    return false;

  int   n= curve_x_poly.characteristic_->mpSize();
  bnum* a= curve_x_poly.c_array_[1];
  bnum* b= curve_x_poly.c_array_[0];
  bnum* p= curve_x_poly.characteristic_;

  bnum  r(2*n);
  bnum  s(2*n);
  bnum  t(2*n);

  g_phi= (rationalpoly**) new rational_p_t[max+1];
  g_exp_y= new i16[max+1];

  // phi[0]= 0
  g_phi[0]= new rationalpoly(*p, 1, 1, 1, 1); 
  g_phi[0]->numerator->c_array_[0]->m_pValue[0]= 0ULL;
  g_phi[0]->denominator->c_array_[0]->m_pValue[0]= 1ULL;
  g_exp_y[0]= 0;

  // phi[1]= 1
  g_phi[1]= new rationalpoly(*p, 1, 1, 1, 1); 
  g_phi[1]->numerator->c_array_[0]->m_pValue[0]= 1ULL;
  g_phi[1]->denominator->c_array_[0]->m_pValue[0]= 1ULL;
  g_exp_y[1]= 0;

  // phi[2]= 2y
  g_phi[2]= new rationalpoly(*p, 1, 1, 1, 1); 
  g_phi[2]->numerator->c_array_[0]->m_pValue[0]= 2ULL;
  g_phi[2]->denominator->c_array_[0]->m_pValue[0]= 1ULL;
  g_exp_y[2]= 1;

  // phi[3]=  3x^4+6ax^2+12bx-a^2
  // Fix: size depends on a, b and p
  g_phi[3]= new rationalpoly(*p, 5, 1, 1, 1); 
  g_phi[3]->denominator->c_array_[0]->m_pValue[0]= 1ULL;
  g_exp_y[3]= 0;
  g_phi[3]->numerator->c_array_[4]->m_pValue[0]= 3ULL;
  g_phi[3]->numerator->c_array_[3]->m_pValue[0]= 0ULL;
  mpZeroNum(t);
  t.m_pValue[0]= 6ULL;
  mpModMult(t,*a,*p,*(g_phi[3]->numerator->c_array_[2]));
  mpZeroNum(t);
  t.m_pValue[0]= 12ULL;
  mpModMult(t,*b,*p,*(g_phi[3]->numerator->c_array_[1]));
  mpZeroNum(s);
  mpModMult(*a,*a,*p,s);
  mpModSub(g_bnZero,s,*p,*(g_phi[4]->numerator->c_array_[0]));

  // phi[4]= 4y(x^6+5ax^4+20bx^3-5a^2x^2-4abx-8b^2-a^3
  // Fix: size depends on a, b and p
  g_phi[4]= new rationalpoly(*p, 7, 1, 1, 1); 
  g_exp_y[4]= 1;

  g_phi[4]->numerator->c_array_[6]->m_pValue[0]= 1ULL;     // x^6
  g_phi[4]->numerator->c_array_[5]->m_pValue[0]= 0ULL;
  mpZeroNum(t);
  t.m_pValue[0]= 5ULL;
  mpModMult(t,*a,*p,*(g_phi[4]->numerator->c_array_[4]));    // 5ax^4
  mpZeroNum(t);
  t.m_pValue[0]= 20ULL;
  mpModMult(t,*b,*p,*(g_phi[4]->numerator->c_array_[3]));    // 20bx^3
  mpZeroNum(r);
  mpZeroNum(t);
  mpZeroNum(s);
  s.m_pValue[0]= 5ULL;
  mpModMult(*a,*a,*p,t);
  mpModMult(s,t,*p,r);
  mpModSub(g_bnZero,r,*p,*(g_phi[4]->numerator->c_array_[2])); // -5a^2x^2
  mpZeroNum(r);
  mpZeroNum(t);
  mpZeroNum(s);
  mpModMult(*a,*b,*p,t);
  s.m_pValue[0]= 4ULL;
  mpModMult(t,s,*p,r);
  mpModSub(g_bnZero,r,*p,*(g_phi[4]->numerator->c_array_[1])); // -4abx
  mpZeroNum(r);
  mpZeroNum(s);
  mpZeroNum(t);
  mpModMult(*b,*b,*p,t);
  s.m_pValue[0]= 8ULL;
  mpModMult(t,s,*p,r);                             // 8b^2
  mpZeroNum(s);
  mpZeroNum(t);
  mpModMult(*a,*a,*p,s);
  mpModMult(s,*a,*p,t);                             // a^3
  mpZeroNum(s);
  mpModAdd(r,t,*p,s);                              // 8b^2+a^3
  mpModSub(g_bnZero,s,*p,(*g_phi[4]->numerator->c_array_[0])); // -8b^2-a^3
  mpZeroNum(s);
  s.m_pValue[0]= 4ULL;
  g_phi[4]->numerator->MultiplyByNum(s);

  int i;
  oddphirecurrence(2, curve_x_poly);
  for(i=3; i<=(max-1)/2; i+=2) {
    if(!evenphirecurrence(i, curve_x_poly))
      return false;
    if(!oddphirecurrence(i, curve_x_poly))
      return false;
  }
  g_maxcoeff= max+1;
  return true;
}

bool Reconcile(int m, polynomial& s, polynomial& u, polynomial& q, polynomial& w) {
  return true;
}

// calculate phi[2m+1]
// phi[2m+1]= phi[m+2]phi^3[m]-phi[m-1]phi^3[m+1]
bool oddphirecurrence(int m, polynomial& curve_x_poly) {
  bnum*       p= curve_x_poly.characteristic_;
  int         n= p->mpSize();
  polynomial  r(*p,(2*m+1)*(2*m+1), 2*n);
  polynomial  s(*p,(2*m+1)*(2*m+1), 2*n);
  polynomial  t(*p,(2*m+1)*(2*m+1), 2*n);
  polynomial  u(*p,(2*m+1)*(2*m+1), 2*n);
  polynomial  v(*p,(2*m+1)*(2*m+1), 2*n);
  polynomial  w(*p,(2*m+1)*(2*m+1), 2*n);

  g_phi[2*m+1]= new rationalpoly(*p, (2*m+1)*(2*m+1), n, (2*m+1)*(2*m+1), n);
  r.ZeroPoly();
  s.ZeroPoly();
  t.ZeroPoly();
  if(!PolyMult(*g_phi[m+2]->numerator, *g_phi[m]->numerator, t))
    return false;
  if(!PolyMult(t, *g_phi[m]->numerator, s))
    return false;
  if(!PolyMult(s, *g_phi[m]->numerator, r))
    return false;
  // r now has the product of the numerators of phi[m+2] and phi^3[m]
  s.ZeroPoly();
  t.ZeroPoly();
  if(!PolyMult(*g_phi[m+2]->denominator, *g_phi[m]->denominator, t))
    return false;
  if(!PolyMult(t, *g_phi[m]->denominator, s))
    return false;
  if(!PolyMult(s, *g_phi[m]->denominator, r))
    return false;
  // u now has the product of the denominators of phi[m+2] and phi^3[m]

  t.ZeroPoly();
  s.ZeroPoly();
  v.ZeroPoly();
  w.ZeroPoly();
  if(!PolyMult(*g_phi[m-1]->numerator, *g_phi[m+1]->numerator, s))
    return false;
  if(!PolyMult(s, *g_phi[m+1]->numerator, t))
    return false;
  if(!PolyMult(t, *g_phi[m+1]->numerator, v))
    return false;
  // v now has the product of the numerators of phi[m-1] and phi^3[m+1]
  t.ZeroPoly();
  s.ZeroPoly();
  if(!PolyMult(*g_phi[m-1]->denominator, *g_phi[m+1]->denominator, s))
    return false;
  if(!PolyMult(s, *g_phi[m+1]->denominator, t))
    return false;
  if(!PolyMult(t, *g_phi[m+1]->denominator, w))
    return false;
  // w now has the product of the denominators of phi[m-1] and phi^3[m+1]

  g_exp_y[2*m+1]= g_exp_y[m+2]+g_exp_y[m]+g_exp_y[m]+g_exp_y[m];
  if(!Reconcile(2*m+1,r,u,v,w))
    return false;
  return true;
}

// calculate phi[2m]
// phi[2m]= phi[m]/phi[2](phi[m+2]phi^2[m-1]-phi[m-2]phi^2[m+1])
bool evenphirecurrence(int m, polynomial& curve_x_poly) {
  bnum*       p= curve_x_poly.characteristic_;
  int         n= p->mpSize();
  polynomial  q(*p,(2*m+1)*(2*m+1), 2*n);
  polynomial  r(*p,(2*m+1)*(2*m+1), 2*n);
  polynomial  s(*p,(2*m+1)*(2*m+1), 2*n);
  polynomial  t(*p,(2*m+1)*(2*m+1), 2*n);
  polynomial  u(*p,(2*m+1)*(2*m+1), 2*n);
  polynomial  v(*p,(2*m+1)*(2*m+1), 2*n);
  polynomial  w(*p,(2*m+1)*(2*m+1), 2*n);

  if(!PolyMult(*g_phi[m+2]->numerator, *g_phi[m-1]->numerator, t))
    return false;
  if(!PolyMult(t, *g_phi[m-1]->numerator, r))
    return false;
  // r now has the product of the numerators phi[m+2] and phi^2[m-1]
  t.ZeroPoly();
  if(!PolyMult(*g_phi[m+2]->denominator, *g_phi[m-1]->denominator, t))
    return false;
  if(!PolyMult(t, *g_phi[m-1]->denominator, u))
    return false;
  // u now has the product of the denominators of phi[m+2] and phi^2[m-1]

  t.ZeroPoly();
  if(!PolyMult(*g_phi[m-2]->numerator, *g_phi[m+1]->numerator, t))
    return false;
  if(!PolyMult(t, *g_phi[m+1]->numerator, v))
    return false;
  // v now has has the product of the numerators of phi[m-2] and phi^2[m+1]
  t.ZeroPoly();
  if(!PolyMult(*g_phi[m-2]->denominator, *g_phi[m+1]->denominator, t))
    return false;
  if(!PolyMult(t, *g_phi[m+1]->denominator, w))
    return false;
  // w now has has the product of the denominators of phi[m-2] and phi^2[m+1]

  // now multiply phi[m]/phi[2]
  bnum       c(1);
  c.m_pValue[0]= 2ULL;
  u.MultiplyByNum(c);
  w.MultiplyByNum(c);
  if(!PolyMult(r, *g_phi[m]->numerator, s))
    return false;
  if(!PolyMult(v, *g_phi[m]->numerator, q))
    return false;
  g_exp_y[2*m]= g_exp_y[m+2]+g_exp_y[m-1]+g_exp_y[m-1]+g_exp_y[m]-g_exp_y[2];
  if(!Reconcile(2*m,s,u,q,w))
    return false;
  return true;
}


// ----------------------------------------------------------------------------